package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.dataflow.expression.ParsedExpr;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.TypeHintCollector;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.graph.CallGraph;
import typeforge.base.node.CallSite;
import typeforge.base.node.FunctionNode;
import typeforge.utils.Global;
import typeforge.utils.Logging;
import typeforge.base.dataflow.expression.NMAE;
import ghidra.program.model.listing.Function;


import java.io.File;
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

    public HashMap<Function, IntraSolver> intraSolverMap;

    public AccessPoints APs;
    public TFGManager graphManager;
    public NMAEManager exprManager;
    public TypeHintCollector typeHintCollector;

    /** Recording malloc/calloc function's callsites */
    public Set<CallSite> mallocCS;
    public Set<CallSite> callocCs;

    public InterSolver(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.visitedFunc = new HashSet<>();
        this.stitchedFunc = new HashSet<>();
        this.intraSolverMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.graphManager = new TFGManager();
        this.exprManager = new NMAEManager(this.graphManager);
        this.typeHintCollector = new TypeHintCollector(exprManager);

        this.mallocCS = new HashSet<>();
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
                // It's common because some functions has primitive return type which we don't trace
                if (retExprs.isEmpty()) {
                    Logging.warn("InterSolver",
                            String.format("CallSite %s has receiver but callee %s has no traced return expression",
                                    callSite, calleeNode.value.getName()));
                    continue;
                }

                for (var recevierExpr: recevierFacts) {
                    for (var retExpr: retExprs) {
                        addInterTFGEdges(retExpr, calleeNode,
                                recevierExpr, funcNode,
                                TypeFlowGraph.EdgeType.RETURN);
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
            mallocCS.add(callSite);
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
        graphManager.earlyTFGStatistics();

        simpleConstantPropagation();

//        // Parsing all fieldAccess Expressions first to build the constraint's skeleton
//        for (var symExpr : exprManager.getFieldExprSet()) {
//            buildConstraintByFieldAccessExpr(symExpr, null, 0);
//        }
//
//        buildSkeletons(typeHintCollector);
//
//
//        /* Following handler's order is important */
//        typeHintCollector.mergeSkeletons();
//        /* Important: handle Type Alias first, then handle Final Constraint. Due to Type Alias may have a negative impact on soundness */
//        typeHintCollector.handleTypeAlias();
//        typeHintCollector.handleFinalConstraint();
//        typeHintCollector.handleAPSets();
//        typeHintCollector.handleUnreasonableSkeleton();
//        typeHintCollector.handlePtrReference();
//        // typeHintCollector.handleDecompilerInferredTypes();
//        typeHintCollector.handleNesting(exprManager.getExprsByAttribute(NMAE.Attribute.ARGUMENT));
//        typeHintCollector.handleMemberConflict();
//        // skeletonCollector.handleCodePtr(symExprManager.getExprsByAttribute(SymbolExpr.Attribute.CODE_PTR));
    }

    /**
     * This Simple Constant Propagation is used to propagate the constant arguments and check if they can propagate to the sensitive function's arguments.
     * If so, we need update related TypeConstraints.
     * For example, if
     *  1. const_callsite_arg_1 -> wrapper_func_param1 -> malloc's size
     *  2. const_callsize_arg_2 -> wrapper_func_param1 -> malloc's size
     *  And there's also a path from malloc's return value to corresponding callsite's reciver
     *  Then this receiver's TypeConstraint's size should be set.
     *  And the wrapper function should also be identified and marked.
     */
    private void simpleConstantPropagation() {
        for (var cs: callocCs) {
            if (cs.caller.getName().equals("ck_calloc")) {
                var arg1 = cs.arguments.get(0);
                var arg2 = cs.arguments.get(1);
                var receiver = cs.receiver;
                var arg1Facts = intraSolverMap.get(cs.caller).getDataFlowFacts(arg1);
                for (var arg1Fact: arg1Facts) {
                    graphManager.dumpPartialTFG(arg1Fact, 5, new File(Global.outputDirectory));
                }
            }
        }
    }


    private void buildSkeletons(TypeHintCollector collector) {
        Logging.debug("InterContext", "========================= Start to merge type constraints =========================");
        Logging.debug("InterContext", "Total Graph Number: " + graphManager.getGraphs().size());
        graphManager.buildAllPathManagers();

        Set<Function> evilFunctions = new HashSet<>();

        // Remove some redundant edges in the graph
        for (var graph: graphManager.getGraphs()) {
            if (graph.pathManager.hasSrcSink) {
                Logging.debug("InterContext", String.format("*********************** Handle Graph %s ***********************", graph));
                // Round1: used to find and mark the evil nodes (Introduced by type ambiguity) and remove the evil edges
                graph.pathManager.tryMergeOnPath(exprManager);
                graph.pathManager.tryMergePathsFromSameSource(exprManager);
                graph.pathManager.tryHandleConflictNodes();
                var removeEdges = graph.pathManager.getEdgesToRemove();
                for (var edge: removeEdges) {
                    graph.getGraph().removeEdge(edge);
                }

                collector.updateEvilSource(graph.pathManager.evilSource,
                        graph.pathManager.evilSourceLCSEdges, graph.pathManager.evilSourceEndEdges);
                collector.updateEvilNodes(graph.pathManager.evilNodes,
                        graph.pathManager.evilNodeEdges);
                evilFunctions.addAll(graph.pathManager.evilFunction);
            }
        }

        for (var graph: graphManager.getGraphs()) {
            for (var node: graph.getGraph().vertexSet()) {
                if (evilFunctions.contains(node.function)) {
                    /* We don't remove edges of expressions that indicate parameters and local variables */
                    if (node.getRootSymExpr().isParameter || node.getRootSymExpr().isReturnVal || node.isRootSymExpr()) {
                        continue;
                    }
                    else {
                        Logging.debug("InterContext", String.format("Found injured node in function %s: %s", node.function, node));
                        collector.injuredNode.add(node);
                        for (var edge: graph.getGraph().edgesOf(node)) {
                            graph.getGraph().removeEdge(edge);
                        }
                    }
                }
            }
        }

        for (var graph: graphManager.getGraphs()) {
            if (!graph.rebuildPathManager() || !graph.pathManager.hasSrcSink) {
                continue;
            }
            graph.pathManager.mergeOnPath(exprManager);
            graph.pathManager.mergePathsFromSameSource();
            graph.pathManager.buildSkeletons(collector);

            collector.updateEvilPaths(graph.pathManager.evilPaths);
        }
    }

    /**
     * Parse the Field Access SymbolExpr and build the constraints for it.
     * For example: if there is a statement: *(a + 0x8) = b, the FieldAccess Expression is *(a + 0x8)
     * @param expr the Expression to parse
     * @param parentTypeConstraint if the expr is a recursive dereference, the parentTypeConstraint is the constraint of the parent expr
     * @param derefDepth the dereference depth of the expr
     */
    private void buildConstraintByFieldAccessExpr(NMAE expr, TypeConstraint parentTypeConstraint, long derefDepth) {
        if (expr == null) return;

        Logging.debug("InterContext", String.format("Parsing FieldAccess Expression %s, parentTypeConstraint: %s, derefDepth: %d",
                expr, parentTypeConstraint != null ? parentTypeConstraint : "null", derefDepth));

        ParsedExpr parsed;
        if (!expr.isDereference()) {
            Logging.error("InterContext", String.format("Current Expression %s is not a field access expression", expr));
            return;
        } else {
            var parsedExpr = ParsedExpr.parseFieldAccessExpr(expr);
            if (parsedExpr.isEmpty()) { return; }
            parsed = parsedExpr.get();
        }

        var baseConstraint = exprManager.getOrCreateConstraint(parsed.base);
        updateFieldAccessConstraint(baseConstraint, parsed.offsetValue, expr);
        exprManager.addFieldRelation(parsed.base, parsed.offsetValue, expr);
        if (parentTypeConstraint != null) {
            baseConstraint.addFieldAttr(parsed.offsetValue, TypeConstraint.Attribute.POINTER);
        }

        if (parsed.index != null && parsed.scale != null) {
            if (parsed.scale.isNoZeroConst()) {
                baseConstraint.setElementSize(parsed.scale.getConstant());
            }
        }

        // If base is still dereference expr, means base is a field with pointer type which points to a composite data type.
        if (parsed.base.isDereference()) {
            buildConstraintByFieldAccessExpr(parsed.base, baseConstraint, derefDepth + 1);
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


    private void updateFieldAccessConstraint(TypeConstraint baseConstraint, long offsetValue, NMAE fieldExpr) {
        var fieldAPs = APs.getFieldAccessPoints(fieldExpr);
        baseConstraint.addFieldExpr(offsetValue, fieldExpr);
        for (var ap: fieldAPs) {
            baseConstraint.addFieldAccess(offsetValue, ap);
        }
    }
}
