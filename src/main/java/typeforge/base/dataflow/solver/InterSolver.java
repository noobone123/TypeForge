package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.dataflow.expression.ParsedExpr;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.skeleton.SkeletonCollector;
import typeforge.base.dataflow.skeleton.TypeConstraint;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.graph.CallGraph;
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

    public HashMap<FunctionNode, IntraSolver> intraSolverMap;

    public AccessPoints APs;
    public TFGManager graphManager;
    public NMAEManager symExprManager;
    public SkeletonCollector skeletonCollector;

    public InterSolver(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.visitedFunc = new HashSet<>();
        this.stitchedFunc = new HashSet<>();
        this.intraSolverMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.graphManager = new TFGManager();
        this.symExprManager = new NMAEManager(this.graphManager);
        this.skeletonCollector = new SkeletonCollector(symExprManager);
    }

    public IntraSolver createIntraSolver(FunctionNode funcNode) {
        IntraSolver intraSolver =
                new IntraSolver(funcNode, symExprManager, graphManager, APs);

        intraSolverMap.put(funcNode, intraSolver);
        return intraSolver;
    }

    public IntraSolver getIntraSolver(FunctionNode funcNode) {
        return intraSolverMap.get(funcNode);
    }

    /**
     * Build the whole program TFG by stitching all the function TFGs together.
     */
    public void buildWholeProgramTFG() {
        while (!workList.isEmpty()) {
            var funcNode = workList.poll();
            if (!funcNode.isMeaningful) {
                Logging.info("InterSolver", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }
            stitchTFG(funcNode);
            stitchedFunc.add(funcNode);
        }

        if (stitchedFunc.size() == visitedFunc.size()) {
            Logging.info("InterSolver", String.format("Stitching succeeded: %d/%d functions are stitched",
                    stitchedFunc.size(), visitedFunc.size()));
        } else {
            Logging.warn("InterSolver", String.format("Stitching failed: %d/%d functions are stitched",
                    stitchedFunc.size(), visitedFunc.size()));
        }
    }

    /**
     * Stitch the TFG by argument <-> parameter, return value <-> receiver
     * @param funcNode the stitching function
     */
    private void stitchTFG(FunctionNode funcNode) {
        Logging.info("InterSolver", String.format("Stitching function %s", funcNode.value.getName()));

        var intraSolver = intraSolverMap.get(funcNode);
        var bridgeInfo = intraSolver.bridgeInfo;
        // Iterate each callSite in the function
        for (var callSite: bridgeInfo.keySet()) {
            var calleeNode = callGraph.getNodebyAddr(callSite.calleeAddr);
            if (calleeNode == null) {
                Logging.warn("InterSolver", "Callee node is null: " + callSite.calleeAddr);
                continue;
            }

            if (calleeNode.isExternal) {
                Logging.debug("InterSolver", "Callee node is external: " + callSite.calleeAddr);
            }
            // We should keep the callee function is already stitched when we are stitching the caller function
            else {
                Logging.debug("InterSolver", "Callee node is normal");

                // Handling arguments and parameters
                var considerParamNum = 0;
                if (calleeNode.isVarArg) {
                    Logging.info("InterSolver", "Callee node is vararg: " + callSite.calleeAddr);
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
                        intraSolver.addTFGEdges(argExpr, paramExpr, TypeFlowGraph.EdgeType.CALL);
                    }
                }

                // Handling return value and receiver
                if (!callSite.hasReceiver()) {
                    continue;
                }

                var recevierVn = callSite.receiver;
                var recevierFacts = bridgeInfo.get(callSite).get(recevierVn);
                var retExprs = intraSolverMap.get(calleeNode).getReturnExpr();
                if (retExprs.isEmpty()) {
                    Logging.warn("InterSolver",
                            String.format("Callsite %s has receiver but callee %s has no traced return expression",
                                    callSite, calleeNode.value.getName()));
                    continue;
                }

                for (var recevierExpr: recevierFacts) {
                    for (var retExpr: retExprs) {
                        intraSolver.addTFGEdges(retExpr, recevierExpr, TypeFlowGraph.EdgeType.RETURN);
                    }
                }
            }
        }
    }

    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void collectSkeletons() {
        // Parsing all fieldAccess Expressions first to build the constraint's skeleton
        for (var symExpr : symExprManager.getFieldExprSet()) {
            buildConstraintByFieldAccessExpr(symExpr, null, 0);
        }

        buildSkeletons(skeletonCollector);


        /* Following handler's order is important */
        skeletonCollector.mergeSkeletons();
        /* Important: handle Type Alias first, then handle Final Constraint. Due to Type Alias may have a negative impact on soundness */
        skeletonCollector.handleTypeAlias();
        skeletonCollector.handleFinalConstraint();
        skeletonCollector.handleAPSets();
        skeletonCollector.handleUnreasonableSkeleton();
        skeletonCollector.handlePtrReference();
        skeletonCollector.handleDecompilerInferredTypes();
        skeletonCollector.handleNesting(symExprManager.getExprsByAttribute(NMAE.Attribute.ARGUMENT));
        skeletonCollector.handleMemberConflict();
        // skeletonCollector.handleCodePtr(symExprManager.getExprsByAttribute(SymbolExpr.Attribute.CODE_PTR));
    }


    private void buildSkeletons(SkeletonCollector collector) {
        Logging.info("InterContext", "========================= Start to merge type constraints =========================");
        Logging.info("InterContext", "Total Graph Number: " + graphManager.getGraphs().size());
        graphManager.buildAllPathManagers();

        Set<Function> evilFunctions = new HashSet<>();

        // Remove some redundant edges in the graph
        for (var graph: graphManager.getGraphs()) {
            if (graph.pathManager.hasSrcSink) {
                Logging.info("InterContext", String.format("*********************** Handle Graph %s ***********************", graph));
                // Round1: used to find and mark the evil nodes (Introduced by type ambiguity) and remove the evil edges
                graph.pathManager.tryMergeOnPath(symExprManager);
                graph.pathManager.tryMergePathsFromSameSource(symExprManager);
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
                        Logging.info("InterContext", String.format("Found injured node in function %s: %s", node.function, node));
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
            graph.pathManager.mergeOnPath(symExprManager);
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

        Logging.info("InterContext", String.format("Parsing FieldAccess Expression %s, parentTypeConstraint: %s, derefDepth: %d",
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

        var baseConstraint = symExprManager.getOrCreateConstraint(parsed.base);
        updateFieldAccessConstraint(baseConstraint, parsed.offsetValue, expr);
        symExprManager.addFieldRelation(parsed.base, parsed.offsetValue, expr);
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

    private void updateFieldAccessConstraint(TypeConstraint baseConstraint, long offsetValue, NMAE fieldExpr) {
        var fieldAPs = APs.getFieldAccessPoints(fieldExpr);
        baseConstraint.addFieldExpr(offsetValue, fieldExpr);
        for (var ap: fieldAPs) {
            baseConstraint.addFieldAccess(offsetValue, ap);
        }
    }

    public boolean isFunctionSolved(FunctionNode funcNode) {
        return visitedFunc.contains(funcNode);
    }
}
