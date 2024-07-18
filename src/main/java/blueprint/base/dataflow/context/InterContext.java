package blueprint.base.dataflow.context;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr.ParsedExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.skeleton.SkeletonCollector;
import blueprint.base.dataflow.typeRelation.TypeRelationGraph;
import blueprint.base.dataflow.types.PrimitiveTypeDescriptor;
import blueprint.base.dataflow.skeleton.TypeConstraint;
import blueprint.base.dataflow.typeRelation.TypeRelationManager;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.PcodeOp;


import java.util.*;

/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 */
public class InterContext {

    public CallGraph callGraph;
    /** The workList queue of the whole program */
    public Queue<FunctionNode> workList;
    /** The set of solved functions */
    public Set<FunctionNode> solvedFunc;

    public HashMap<FunctionNode, IntraContext> intraCtxMap;

    public AccessPoints APs;
    public TypeRelationManager<SymbolExpr> typeRelationManager;
    public Set<SymbolExpr> fieldExprCandidates;
    public SymbolExprManager symExprManager;

    public InterContext(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.solvedFunc = new HashSet<>();
        this.intraCtxMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.typeRelationManager = new TypeRelationManager<>();
        this.fieldExprCandidates = new HashSet<>();
        this.symExprManager = new SymbolExprManager(this);
    }

    public void createIntraContext(FunctionNode funcNode) {
        IntraContext intraCtx = new IntraContext(funcNode, symExprManager);
        intraCtxMap.put(funcNode, intraCtx);
    }

    public IntraContext getIntraContext(FunctionNode funcNode) {
        return intraCtxMap.get(funcNode);
    }

    public void addFieldAccessExpr(SymbolExpr expr, PcodeOp pcodeOp, DataType dt, AccessPoints.AccessType accessType) {
        fieldExprCandidates.add(expr);
        APs.addFieldAccessPoint(expr, pcodeOp, dt, accessType);
    }

    public void addTypeRelation(SymbolExpr from, SymbolExpr to, TypeRelationGraph.EdgeType edgeType) {
        if (from.equals(to)) {
            return;
        }

        if (isMergedVariableExpr(from) || isMergedVariableExpr(to)) {
            Logging.info("InterContext", String.format("Skip adding type alias relation between merged variables: %s and %s", from, to));
            return;
        }

        typeRelationManager.addEdge(from, to, edgeType);
    }

    public boolean addMemoryAliasRelation(SymbolExpr from, SymbolExpr to) {
        if (from.equals(to)) {
            return false;
        }
        // If there is already an existing edge between from and to, we don't need to add a new one.
        if (typeRelationManager.hasEdge(from, to)) {
            Logging.debug("InterContext", String.format("There is already an existing edge between %s and %s", from, to));
            return false;
        }
        if (isMergedVariableExpr(from) || isMergedVariableExpr(to)) {
            Logging.info("InterContext", String.format("Skip adding type alias relation between merged variables: %s and %s", from, to));
            return false;
        }

        typeRelationManager.addEdge(from, to, TypeRelationGraph.EdgeType.MEMALIAS);
        return true;
    }


    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void collectSkeletons() {
        // Parsing all fieldAccess Expressions first to build the constraint's skeleton
        for (var symExpr : fieldExprCandidates) {
            buildConstraintByFieldAccessExpr(symExpr, null, 0);
        }

        var skeletonCollectior = new SkeletonCollector(symExprManager);
        buildSkeletons(skeletonCollectior);

        skeletonCollectior.mergeSkeletons();
        skeletonCollectior.handleTypeAlias();
        skeletonCollectior.handlePtrReference();

//        handleExprWithAttributions();
//        // Remove meaningLess constraints
//        removeRedundantConstraints();
    }


    private void buildSkeletons(SkeletonCollector collector) {
        Logging.info("InterContext", "========================= Start to merge type constraints =========================");
        Logging.info("InterContext", "Total Graph Number: " + typeRelationManager.getGraphs().size());
        typeRelationManager.buildAllPathManagers();

        // TODO: add evil nodes information into SkeletonCollector
        // Remove some redundant edges in the graph
        for (var graph: typeRelationManager.getGraphs()) {
            if (graph.pathManager.hasSrcSink) {
                Logging.info("InterContext", String.format("*********************** Handle Graph %s ***********************", graph));
                // Round1: used to find and mark the evil nodes (Introduced by type ambiguity) and remove the evil edges
                graph.pathManager.tryMergeOnPath(symExprManager);
                graph.pathManager.tryMergePathsFromSameSource();
                var removeEdges = graph.pathManager.handleConflictNodes();
                for (var edge: removeEdges) {
                    graph.getGraph().removeEdge(edge);
                }
            }
        }

        for (var graph: typeRelationManager.getGraphs()) {
            if (!graph.rebuildPathManager() || !graph.pathManager.hasSrcSink) {
                continue;
            }
            // This time, try MergeOnPath will not appear conflicts because we have already removed these evil edges.
            graph.pathManager.tryMergeOnPath(symExprManager);
            graph.pathManager.mergePathsFromSameSource();
            graph.pathManager.buildSkeletons(collector);
        }
    }

    /**
     * Parse the Field Access SymbolExpr and build the constraints for it.
     * For example: if there is a statement: *(a + 0x8) = b, the FieldAccess Expression is *(a + 0x8)
     * @param expr the Expression to parse
     * @param parentTypeConstraint if the expr is a recursive dereference, the parentTypeConstraint is the constraint of the parent expr
     * @param derefDepth the dereference depth of the expr
     */
    private void buildConstraintByFieldAccessExpr(SymbolExpr expr, TypeConstraint parentTypeConstraint, long derefDepth) {
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

//    /**
//     * Handle the SymbolExpressions with some special attributes. Like Argument, CodePTR, ...
//     */
//    private void handleExprWithAttributions() {
//        for (var expr: symExprManager.getExprsByAttribute(SymbolExpr.Attribute.ARGUMENT)) {
//            if (symExprManager.getConstraint(expr) == null || !symExprManager.getConstraint(expr).isInterested()) {
//                continue;
//            }
//
//            // If there is a base + offset Expression as an argument, we should update the nested constraint
//            if (expr.hasBase() && expr.hasOffset() && expr.getOffset().isNoZeroConst()) {
//                var base = expr.getBase();
//                var offset = expr.getOffset().getConstant();
//                var nestedConstraint = symExprManager.getConstraint(expr);
//                updateNestedConstraint(symExprManager.getConstraint(base), offset, nestedConstraint);
//                Logging.info("Context", String.format("There may exist a nested constraint in %s: offset 0x%x", expr, offset));
//            }
//        }
//
//        // Handle the CodePTR
//        for (var expr: symExprManager.getExprsByAttribute(SymbolExpr.Attribute.CODE_PTR)) {
//            if (expr.isDereference()) {
//                var parsed = ParsedExpr.parseFieldAccessExpr(expr);
//                if (parsed.isEmpty()) { return; }
//                var base = parsed.get().base;
//                var offset = parsed.get().offsetValue;
//                var constraint = symExprManager.getConstraint(base);
//                constraint.addFieldAttr(offset, TypeConstraint.Attribute.CODE_PTR);
//            }
//        }
//    }

//    private void updateNestedConstraint(TypeConstraint nester, long offsetValue, TypeConstraint nestee) {
//        nester.addNestTo(offsetValue, nestee);
//        nestee.addNestedBy(nester, offsetValue);
//        nester.addFieldAttr(offsetValue, TypeConstraint.Attribute.MAY_NESTED);
//    }

    private void updateFieldAccessConstraint(TypeConstraint baseConstraint, long offsetValue, SymbolExpr fieldExpr) {
        var fieldAPs = APs.getFieldAccessPoints(fieldExpr);
        baseConstraint.addFieldExpr(offsetValue, fieldExpr);
        for (var ap: fieldAPs) {
            baseConstraint.addFieldAccess(offsetValue, ap);
        }
    }

    private boolean isMergedVariableExpr(SymbolExpr expr) {
        if (expr.isTemp) { return false; }
        var rootSym = expr.getRootHighSymbol();
        if (rootSym.isGlobal()) { return false; }
        var function = rootSym.getHighFunction().getFunction();
        var funcNode = callGraph.getNode(function);
        if (funcNode.mergedVariables.isEmpty()) { return false; }
        else {
            return funcNode.mergedVariables.contains(rootSym);
        }
    }

    private boolean checkOffsetSize(TypeConstraint constraint, long offset, int wantedSize) {
        boolean result = true;
        for (var access: constraint.fieldAccess.get(offset)) {
            if (access.dataType instanceof PrimitiveTypeDescriptor primDataType) {
                if (primDataType.getDataTypeSize() != wantedSize) {
                    result = false;
                    break;
                }
            }
        }
        return result;
    }

    public AccessPoints getAccessPoints() {
        return APs;
    }

    public boolean isFunctionSolved(FunctionNode funcNode) {
        return solvedFunc.contains(funcNode);
    }
}
