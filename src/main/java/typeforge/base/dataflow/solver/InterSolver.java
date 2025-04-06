package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.dataflow.expression.ParsedExpr;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.graph.CallGraph;
import typeforge.base.node.CallSite;
import typeforge.base.node.FunctionNode;
import typeforge.utils.Logging;
import typeforge.base.dataflow.expression.NMAE;
import ghidra.program.model.listing.Function;


import java.util.*;

/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 */
public class InterSolver {

    public CallGraph callGraph;
    /** The workList queue of the whole program */
    public Queue<FunctionNode> workList;
    /** The set of solved functions */
    public Set<FunctionNode> visitedFunc;
    /** The set of functions that are stitched with its callee */
    public Set<FunctionNode> stitchedFunc;

    public Map<CallSite, FunctionNode> callSiteToCallee;
    public Map<FunctionNode, Set<CallSite>> calleeToCallSites;

    public HashMap<Function, IntraSolver> intraSolverMap;

    public AccessPoints APs;
    public TFGManager graphManager;
    public NMAEManager exprManager;

    public ConstPropagator constPropagator;
    public LayoutPropagator layoutPropagator;
    public TypeHintCollector typeHintCollector;

    /** Recording malloc/calloc function's callsites */
    public Set<CallSite> mallocCs;
    public Set<CallSite> callocCs;

    public InterSolver(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();

        this.visitedFunc = new HashSet<>();
        this.stitchedFunc = new HashSet<>();

        this.callSiteToCallee = new HashMap<>();
        this.calleeToCallSites = new HashMap<>();

        this.intraSolverMap = new HashMap<>();
        this.APs = new AccessPoints();

        this.graphManager = new TFGManager();
        this.exprManager = new NMAEManager(this.graphManager);

        this.constPropagator = new ConstPropagator(this);
        this.layoutPropagator = new LayoutPropagator(this);
        this.typeHintCollector = new TypeHintCollector(this);

        // These CallSite is useful for Constant Propagation
        this.mallocCs = new HashSet<>();
        this.callocCs = new HashSet<>();
    }

    public IntraSolver createIntraSolver(FunctionNode funcNode) {
        IntraSolver intraSolver =
                new IntraSolver(funcNode, exprManager, graphManager, APs);

        intraSolverMap.put(funcNode.value, intraSolver);
        return intraSolver;
    }

    /**
     * Build the whole program TFG by stitching all the function TFGs together.
     */
    public void buildWholeProgramTFG() {
        while (!workList.isEmpty()) {
            var funcNode = workList.poll();
            if (!funcNode.isMeaningful) {
                Logging.debug("InterSolver", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }
            stitchTFG(funcNode);
            stitchedFunc.add(funcNode);
        }

        if (stitchedFunc.size() == visitedFunc.size()) {
            Logging.info("InterSolver", String.format("Stitching succeeded: %d/%d functions are stitched",
                    stitchedFunc.size(), visitedFunc.size()));
        } else {
            Logging.warn("InterSolver", String.format("Stitching has something wrong: %d/%d functions are stitched",
                    stitchedFunc.size(), visitedFunc.size()));
        }
    }

    /**
     * Stitch the TFG by argument <-> parameter, return value <-> receiver
     * @param funcNode the stitching function
     */
    private void stitchTFG(FunctionNode funcNode) {
        Logging.debug("InterSolver", String.format("Stitching function %s", funcNode.value.getName()));

        var intraSolver = intraSolverMap.get(funcNode.value);
        var bridgeInfo = intraSolver.bridgeInfo;
        // Iterate each callSite in the function
        for (var callSite: bridgeInfo.keySet()) {
            var calleeNode = callGraph.getNodebyAddr(callSite.calleeAddr);
            if (calleeNode == null) {
                Logging.warn("InterSolver", "Callee node is null: " + callSite.calleeAddr);
                continue;
            }

            // Recording the CallSite Information.
            callSiteToCallee.put(callSite, calleeNode);
            calleeToCallSites.computeIfAbsent(
                    calleeNode,
                    k -> new HashSet<>()
            ).add(callSite);

            // Do Stitching
            if (calleeNode.isExternal) {
                Logging.trace("InterSolver", "Callee node is external: " + callSite.calleeAddr);
                handleExternalCall(callSite, calleeNode, intraSolver);
            }
            // We should keep the callee function is already stitched when we are stitching the caller function
            else {
                Logging.trace("InterSolver", "Callee node is normal");

                // Handling arguments and parameters
                var considerParamNum = 0;
                if (calleeNode.isVarArg) {
                    Logging.debug("InterSolver", "Callee node is vararg: " + callSite.calleeAddr);
                    considerParamNum = calleeNode.fixedParamNum;
                } else {
                    considerParamNum = calleeNode.parameters.size();
                }

                for (int argIdx = 0; argIdx < considerParamNum; argIdx++) {
                    var argVn = callSite.arguments.get(argIdx);
                    if (!intraSolver.isTracedVn(argVn)) {
                        continue;
                    }

                    var argFacts = bridgeInfo.get(callSite).get(argVn);
                    if (argFacts == null) { continue; }
                    for (var argExpr: argFacts) {
                        var param = calleeNode.parameters.get(argIdx);
                        var paramExpr = new NMAEManager.Builder().rootSymbol(param).build();
                        addInterTFGEdges(argExpr, funcNode,
                                paramExpr, calleeNode,
                                TypeFlowGraph.EdgeType.CALL);
                    }
                }

                // Handling return value and receiver
                if (!callSite.hasReceiver()) {
                    continue;
                }

                var recevierVn = callSite.receiver;
                var recevierFacts = bridgeInfo.get(callSite).get(recevierVn);
                var retExprs = intraSolverMap.get(calleeNode.value).getReturnExpr();

                // It's common because some functions may contain Facts related to primitive types
                // which we are not interested, so we just skip them.
                if (recevierFacts.isEmpty() && retExprs.isEmpty()) {
                    Logging.trace("InterSolver",
                            String.format("CallSite %s is not important so we did not trace them", callSite));
                }
                else if (recevierFacts.isEmpty() && !retExprs.isEmpty()) {
                    Logging.trace("InterSolver",
                            String.format("CallSite %s has no receiver but callee %s has traced return expression",
                                    callSite, calleeNode.value.getName()));
                }
                else if (!recevierFacts.isEmpty() && retExprs.isEmpty()) {
                    Logging.trace("InterSolver",
                            String.format("CallSite %s has receiver but callee %s has no traced return expression",
                                    callSite, calleeNode.value.getName()));
                }
                else {
                    for (var recevierExpr: recevierFacts) {
                        for (var retExpr : retExprs) {
                            addInterTFGEdges(retExpr, calleeNode,
                                    recevierExpr, funcNode,
                                    TypeFlowGraph.EdgeType.RETURN);
                        }
                    }
                }
            }
        }
    }

    /**
     * Handle the external function call.
     * @param callSite the callsite
     * @param calleeNode the callee node
     * @param intraSolver the intraSolver of the caller function
     */
    private void handleExternalCall(CallSite callSite, FunctionNode calleeNode, IntraSolver intraSolver) {
        var externalFuncName = calleeNode.value.getName();
        Logging.trace("InterSolver", "Handling external function: " + externalFuncName);
        if (externalFuncName.equals("malloc")) {
            mallocCs.add(callSite);
        } else if (externalFuncName.equals("calloc")) {
            callocCs.add(callSite);
        }
        ExternalHandler.handle(callSite, externalFuncName, intraSolver, exprManager);
    }

    /**
     * IMPORTANT: This function should be called after the whole program TFG is built.
     * Build the complex data type's constraints for based on the WholeProgram TFG.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void typeHintPropagation() {
        graphManager.simpleTFGStatistics();

        Logging.debug("InterSolver", "Size of callSiteToCallee: " + callSiteToCallee.size());

        // Run the ConstPropagator to propagate the constant information in the TFG
        constPropagator.run();

        // Parsing all fieldAccess Expressions collected in intra-procedural analysis
        for (var expr : exprManager.getFieldAccessExprSet()) {
            collectFieldAccessHints(expr, null, 0);
        }

        layoutPropagator.run();
        typeHintCollector.run();
    }

    /**
     * Collect the field access expressions during intra-procedural analysis.
     * Parse the Field Access SymbolExpr and create the skeletons for it, basic member information should be
     * added into skeletons of decompiler-inferred variables in this step.
     * For example: if there is a statement: *(a + 0x8) = b, the FieldAccess Expression is *(a + 0x8)
     * @param expr the Expression to parse
     * @param outerSkt if the expr is a recursive dereference, the outerSkt is the Skeleton of the outer expr
     * @param derefDepth the dereference depth of the expr
     */
    private void collectFieldAccessHints(NMAE expr, Skeleton outerSkt, long derefDepth) {
        if (expr == null) return;

        Logging.debug("InterSolver", String.format("Parsing FieldAccess Expression %s, outerSkt: %s, derefDepth: %d",
                expr, outerSkt != null ? outerSkt : "null", derefDepth));

        ParsedExpr parsed;
        if (!expr.isDereference()) {
            Logging.error("InterSolver", String.format("Current Expression %s is not a field access expression", expr));
            return;
        } else {
            var parsedExpr = ParsedExpr.parseFieldAccessExpr(expr);
            if (parsedExpr.isEmpty()) { return; }
            parsed = parsedExpr.get();
        }

        var baseSkeleton = exprManager.getOrCreateSkeleton(parsed.base);
        updateFieldAccess(baseSkeleton, parsed.offsetValue, expr);
        exprManager.addFieldRelation(parsed.base, parsed.offsetValue, expr);

        // For example: if parsing *(*(a + 0x8) + 0x2),
        // At 1st level of recursion: base -> *(a + 0x8), offset -> 0x2, outerSkt -> null
        // At 2nd level of recursion: base -> a, offset -> 0x8, outerSkt -> *(a + 0x8)'s skt
        // We can infer that a's member(0x8) is a pointer type.
        if (outerSkt != null) {
            baseSkeleton.addFieldAttr(parsed.offsetValue, Skeleton.Attribute.POINTER);
        }

        if (parsed.index != null && parsed.scale != null) {
            if (parsed.scale.isNoZeroConst()) {
                baseSkeleton.setElementSize(parsed.scale.getConstant());
            }
        }

        // If base is still dereference expr, means base is a field with pointer type which points to a composite data type.
        if (parsed.base.isDereference()) {
            collectFieldAccessHints(parsed.base, baseSkeleton, derefDepth + 1);
        }
    }

    /**
     * Add inter-function edges in the Type Flow Graph
     * @param from the source NMAE
     * @param fromNode the source function node
     * @param to the target NMAE
     * @param toNode the target function node
     * @param edgeType the type of the edge
     */
    public void addInterTFGEdges(NMAE from, FunctionNode fromNode,
                                 NMAE to, FunctionNode toNode,
                                 TypeFlowGraph.EdgeType edgeType) {
        if (fromNode.equals(toNode)) {
            return;
        }

        if (FunctionNode.isMergedVariableExpr(fromNode, from) || FunctionNode.isMergedVariableExpr(toNode, to)) {
            Logging.debug("InterSolver",
                    String.format("Skip adding TFG Edges between merged variables: %s:%s and %s:%s",
                            fromNode.value.getName(), from, toNode.value.getName(), to));
            return;
        }

        graphManager.addEdge(from, to, edgeType);
    }

    /**
     * Update the field access NMAE and APs into base's Skeleton.
     * @param baseSkeleton the base's Skeleton
     * @param offsetValue the offset value of the field access
     * @param fieldExpr the NMAE that indicates the field access
     */
    private void updateFieldAccess(Skeleton baseSkeleton, long offsetValue, NMAE fieldExpr) {
        var fieldAPs = APs.getFieldAccessPoints(fieldExpr);
        baseSkeleton.addFieldExpr(offsetValue, fieldExpr);
        for (var ap: fieldAPs) {
            baseSkeleton.addFieldAccess(offsetValue, ap);
        }
    }
}
