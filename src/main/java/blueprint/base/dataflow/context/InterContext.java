package blueprint.base.dataflow.context;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr.ParsedExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.types.PrimitiveTypeDescriptor;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.base.dataflow.typeAlias.TypeAliasGraph;
import blueprint.base.dataflow.typeAlias.TypeAliasManager;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Global;
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
    public TypeAliasManager<SymbolExpr> typeAliasManager;
    public Set<SymbolExpr> fieldExprParseCandidates;
    public SymbolExprManager symExprManager;

    public InterContext(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.solvedFunc = new HashSet<>();
        this.intraCtxMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.typeAliasManager = new TypeAliasManager<>();
        this.fieldExprParseCandidates = new HashSet<>();
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
        fieldExprParseCandidates.add(expr);
        APs.addFieldAccessPoint(expr, pcodeOp, dt, accessType);
    }

    public void addTypeAliasRelation(SymbolExpr from, SymbolExpr to, TypeAliasGraph.EdgeType edgeType) {
        if (from.equals(to)) {
            return;
        }
        typeAliasManager.addEdge(from, to, edgeType);
    }

    public boolean addMemoryAliasRelation(SymbolExpr from, SymbolExpr to) {
        if (from.equals(to)) {
            return false;
        }
        // If there is already an existing edge between from and to, we don't need to add a new one.
        if (typeAliasManager.hasEdge(from, to)) {
            Logging.debug("InterContext", String.format("There is already an existing edge between %s and %s", from, to));
            return false;
        }
        typeAliasManager.addEdge(from, to, TypeAliasGraph.EdgeType.MEMALIAS);
        return true;
    }


    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void collectConstraints() {
        // Parsing all fieldAccess Expressions first to build the constraint's skeleton
        for (var symExpr : fieldExprParseCandidates) {
            parseFieldAccessExpr(symExpr, null, 0);
        }

        handleMemoryAlias();

        typeAliasManager.removeRedundantGraphs(symExprManager.getBaseToFieldsMap());

        // merging constraints according to type alias graph
        mergeByTypeAliasGraph();

        handleExprWithAttributions();

        // merge constraints in same offset
        mergeConstraints();

        // Remove meaningLess constraints
        removeRedundantConstraints();

        Logging.info("InterContext", "Collect constraints done.");
    }

    /**
     * Current memory alias graph is not complete, it only contains the alias relationship with explicit data-flow relations.
     * And alias relations introduced by memory alias is not handled yet.
     * For example: if `a` and `b` is alias, then `*(a + 0x10)` and `*(b + 0x10)` should be alias too.
     * In this method, we consider fields as type alias only if their bases are alias and offsets are the same.
     */
    private void handleMemoryAlias() {
        var workList = new LinkedList<SimpleEntry>();
        var visited = new HashSet<SimpleEntry>();
        var allBaseExprs = symExprManager.getAllBaseExprs();

        Logging.info("InterContext", "Start to handle memory alias.");
        for (var baseExpr: allBaseExprs) {
            var fieldExprs = symExprManager.getFieldInfo(baseExpr);
            for (var fieldInfo : fieldExprs.entrySet()) {
                var entry = new SimpleEntry(baseExpr, fieldInfo.getKey());
                workList.add(entry);
                Logging.debug("InterContext", String.format("Add baseExpr %s with offset 0x%x", baseExpr, fieldInfo.getKey()));
            }
        }

        while (!workList.isEmpty()) {
            var entry = workList.poll();
            var baseExpr = entry.baseExpr;
            var offset = entry.offset;

            if (visited.contains(entry)) {
                continue;
            }
            Logging.debug("InterContext", String.format("Processing baseExpr %s with offset 0x%x", baseExpr, offset));
            visited.add(entry);
            var currentFieldExprs = symExprManager.getFieldExprsByOffset(baseExpr, offset);
            var otherFieldExprsWithSameOffset = getOtherFieldExprsWithSameOffset(baseExpr, offset, visited);

            if (currentFieldExprs.isEmpty()) { continue; }
            for (var currentFieldExpr: currentFieldExprs.get()) {
                for (var otherFieldExpr : otherFieldExprsWithSameOffset) {
                    if (addMemoryAliasRelation(currentFieldExpr, otherFieldExpr)) {
                        // If a new memory alias relation is added, and new added otherFieldExpr still has fields, we need to add them into workList
                        var newFieldExprs = symExprManager.getFieldInfo(otherFieldExpr);
                        if (newFieldExprs == null) {
                            Logging.debug("InterContext", String.format("Other field expr %s has no fields.", otherFieldExpr));
                        }
                        else {
                            for (var newFieldInfo : newFieldExprs.entrySet()) {
                                workList.add(new SimpleEntry(otherFieldExpr, newFieldInfo.getKey()));
                                Logging.debug("InterContext", String.format("Add otherFieldExpr %s with offset 0x%x", otherFieldExpr, newFieldInfo.getKey()));
                            }
                        }
                    }
                }
            }
        }
    }


    private void mergeByTypeAliasGraph() {
        for (var graph: typeAliasManager.getGraphs()) {
            if (graph.getNumNodes() > 1) {
                var mayTypeAgnosticParams = graph.findMayTypeAgnosticParams();
                if (!mayTypeAgnosticParams.isEmpty()) {
                    var confirmedTypeAgnositicParams = graph.checkTypeAgnosticParams(mayTypeAgnosticParams, symExprManager.getExprToConstraintMapCopy());
                    if (!confirmedTypeAgnositicParams.isEmpty()) {
                        Logging.info("InterContext", "Confirmed type agnostic params found: " + confirmedTypeAgnositicParams);
                        graph.removeTypeAgnosticCallEdgesAndMerge(confirmedTypeAgnositicParams, symExprManager.getExprToConstraintMap(), true);
                    } else {
                        Logging.info("InterContext", "No confirmed type agnostic params found.");
                        graph.mergeNodesConstraints(graph.getNodes(), symExprManager.getExprToConstraintMap(), true);
                    }
                } else {
                    graph.mergeNodesConstraints(graph.getNodes(), symExprManager.getExprToConstraintMap(), true);
                }
            }
        }
    }


    // TODO: checking FieldConflict before merging ...
    private void mergeConstraints() {
        var workList = new LinkedList<TypeConstraint>();
        var allConstraints = symExprManager.getAllConstraints();
        for (var constraint : allConstraints) {
            if (hasMultiReferenceField(constraint)) {
                Logging.info("InterContext", String.format("%s has multi reference fields", constraint));
                workList.add(constraint);
            }
        }

        while (!workList.isEmpty()) {
            var cur = workList.poll();
            mergeMultiReference(cur, workList);
        }
    }


    /**
     * We created Constraints for all HighSymbols in the function, but not all of them can indicate the composite data type.
     * We only want HighSymbol which is:
     * 1. Structure, Array or Union
     * 2. Pointer to Structure, Array or Union
     * So we need to remove these Constraints which are not meaningful.
     */
    private void removeRedundantConstraints() {
        var finalResult = new HashMap<SymbolExpr, TypeConstraint>();
        for (var entry : symExprManager.getExprToConstraintMap().entrySet()) {
            var expr = entry.getKey();
            var constraint = entry.getValue();
            if (constraint.isInterested()) {
                finalResult.put(expr, constraint);
            } else {
                TypeConstraint.remove(constraint);
                Logging.warn("Context", String.format("Remove not interested %s -> Constraint_%s",
                        expr.toString(), constraint.toString()));
            }
        }

        symExprManager.updateAllExprToConstraintMap(finalResult);
    }


    /**
     * Parse the Field Access SymbolExpr and build the constraints for it.
     * For example: if there is a statement: *(a + 0x8) = b, the FieldAccess Expression is *(a + 0x8)
     * @param expr the Expression to parse
     * @param parentTypeConstraint if the expr is a recursive dereference, the parentTypeConstraint is the constraint of the parent expr
     * @param derefDepth the dereference depth of the expr
     */
    private void parseFieldAccessExpr(SymbolExpr expr, TypeConstraint parentTypeConstraint, long derefDepth) {
        if (expr == null) return;

        Logging.info("InterContext", String.format("Parsing FieldAccess Expression %s, parentTypeConstraint: %s, derefDepth: %d",
                expr, parentTypeConstraint != null ? parentTypeConstraint : "null", derefDepth));

        ParsedExpr parsed = null;
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
            updateReferenceConstraint(baseConstraint, parsed.offsetValue, parentTypeConstraint);
        }

        if (parsed.index != null && parsed.scale != null) {
            if (parsed.scale.isNoZeroConst()) {
                baseConstraint.setElementSize(parsed.scale.getConstant());
            }
        }

        // If base is still dereference expr, means base is a field with pointer type which points to a composite data type.
        if (parsed.base.isDereference()) {
            parseFieldAccessExpr(parsed.base, baseConstraint, derefDepth + 1);
        }
    }

    /**
     * Handle the SymbolExpressions with some special attributes. Like Argument, CodePTR, ...
     */
    private void handleExprWithAttributions() {
        // Handle the CallSite Arguments
        for (var expr: symExprManager.getExprsByAttribute(SymbolExpr.Attribute.ARGUMENT)) {
            if (symExprManager.getConstraint(expr) != null && symExprManager.getConstraint(expr).isInterested()
                    && expr.hasBase() && expr.hasOffset() && expr.getOffset().isNoZeroConst()) {
                var base = expr.getBase();
                var offset = expr.getOffset().getConstant();
                var nestedConstraint = symExprManager.getConstraint(expr);
                updateNestedConstraint(symExprManager.getConstraint(base), offset, nestedConstraint);
                Logging.info("Context", String.format("There may exist a nested constraint in %s: offset 0x%x", expr, offset));
            }
        }

        // Handle the CodePTR
        for (var expr: symExprManager.getExprsByAttribute(SymbolExpr.Attribute.CODE_PTR)) {
            if (expr.isDereference()) {
                var parsed = ParsedExpr.parseFieldAccessExpr(expr);
                if (parsed.isEmpty()) { return; }
                var base = parsed.get().base;
                var offset = parsed.get().offsetValue;
                var constraint = symExprManager.getConstraint(base);
                constraint.addFieldAttr(offset, TypeConstraint.Attribute.CODE_PTR);
            }
        }
    }

    private void updateNestedConstraint(TypeConstraint nester, long offsetValue, TypeConstraint nestee) {
        nester.addNestTo(offsetValue, nestee);
        nestee.addNestedBy(nester, offsetValue);
        nester.addFieldAttr(offsetValue, TypeConstraint.Attribute.MAY_NESTED);
    }

    private void updateFieldAccessConstraint(TypeConstraint baseConstraint, long offsetValue, SymbolExpr fieldExpr) {
        var fieldAPs = APs.getFieldAccessPoints(fieldExpr);
        for (var ap: fieldAPs) {
            baseConstraint.addFieldAccess(offsetValue, ap);
        }
    }

    private void updateReferenceConstraint(TypeConstraint referencer, long offsetValue, TypeConstraint referencee) {
        referencee.addReferencedBy(referencer, offsetValue);
        referencer.addReferenceTo(offsetValue, referencee);
    }


    private boolean hasMultiReferenceField(TypeConstraint constraint) {
        for (var entry : constraint.referenceTo.entrySet()) {
            if (entry.getValue().size() > 1) {
                return true;
            }
        }
        return false;
    }

    private void mergeMultiReference(TypeConstraint constraint, LinkedList<TypeConstraint> workList) {
        for (var entry : constraint.referenceTo.entrySet()) {
            if (entry.getValue().size() > 1) {
                Logging.info("Context", String.format("%s has multiple referenceTo at 0x%x", constraint.toString(), entry.getKey()));
                boolean shouldMerge = checkOffsetSize(constraint, entry.getKey(), Global.currentProgram.getDefaultPointerSize());
                if (!shouldMerge) {
                    Logging.warn("Context", String.format("%s has different size at 0x%x when handling multiReference.", constraint, entry.getKey()));
                    continue;
                }

                TypeConstraint newMergedConstraint = new TypeConstraint();
                Logging.debug("Context", String.format("Created new merged constraint: %s", newMergedConstraint));
                var toMerge = new HashSet<>(entry.getValue());
                for (var ref : toMerge) {
                    Logging.debug("Context", String.format("Merging %s to %s", ref, newMergedConstraint));
                    newMergedConstraint.fullMerge(ref);
                }

                if (hasMultiReferenceField(newMergedConstraint)) {
                    workList.add(newMergedConstraint);
                }

                // add the new merged constraint in the symExprToConstraints
                for (var symExpr: newMergedConstraint.getAssociatedExpr()) {
                    symExprManager.updateExprToConstraintMap(symExpr, newMergedConstraint);
                    Logging.info("Context", String.format("Set expr %s -> %s", symExpr, newMergedConstraint));
                }
            }
        }
    }


    private Set<SymbolExpr> getOtherFieldExprsWithSameOffset(SymbolExpr baseExpr, long offset, Set<SimpleEntry> visited) {
        var result = new HashSet<SymbolExpr>();
        var typeAliasGraph = typeAliasManager.getTypeAliasGraph(baseExpr);
        if (typeAliasGraph == null) {
            return result;
        }

        for (var node: typeAliasGraph.getNodes()) {
            if (node.equals(baseExpr)) {
                continue;
            } else {
                var fieldExprs = symExprManager.getFieldExprsByOffset(node, offset);
                if (fieldExprs.isPresent()) {
                    visited.add(new SimpleEntry(node, offset));
                    var exprs = fieldExprs.get();
                    for (var expr : exprs) {
                        if (result.add(expr)) {
                            Logging.debug("InterContext", String.format("Found other field expr %s with same offset 0x%x", expr, offset));
                        }
                    }
                }
            }
        }

        return result;
    }


    static class SimpleEntry {
        final SymbolExpr baseExpr;
        final long offset;

        public SimpleEntry(SymbolExpr baseExpr, long offset) {
            this.baseExpr = baseExpr;
            this.offset = offset;
        }

        @Override
        public int hashCode() {
            return Objects.hash(baseExpr, offset);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            SimpleEntry that = (SimpleEntry) obj;
            return offset == that.offset && baseExpr.equals(that.baseExpr);
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
