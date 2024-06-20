package blueprint.base.dataflow.context;

import blueprint.base.dataflow.AccessPoints;
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
    public Set<SymbolExpr> memAccessExprParseCandidates;
    public Set<SymbolExpr> ArgOrReturnExprParseCandidates;
    public Set<SymbolExpr> fieldExprParseCandidates;
    public SymbolExprManager symExprManager;

    public InterContext(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.solvedFunc = new HashSet<>();
        this.intraCtxMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.typeAliasManager = new TypeAliasManager<>();
        this.memAccessExprParseCandidates = new HashSet<>();
        this.ArgOrReturnExprParseCandidates = new HashSet<>();
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

    public void addArgOrReturnExpr(SymbolExpr expr, PcodeOp pcodeOp, AccessPoints.AccessType accessType) {
        ArgOrReturnExprParseCandidates.add(expr);
        APs.addArgOrReturnAccessPoint(expr, pcodeOp, accessType);
    }

    public void addTypeAliasRelation(SymbolExpr from, SymbolExpr to, TypeAliasGraph.EdgeType edgeType) {
        if (from.equals(to)) {
            return;
        }
        typeAliasManager.addEdge(from, to, edgeType);
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


//        removeRedundantConstraints();
//        // merging
//        mergeByTypeAliasGraph();
//
//        // Parsing all FieldAccessExpr to refine the constraint's skeleton
//        for (var symExpr : fieldExprParseCandidates) {
//            parseFieldAccessExpr(symExpr);
//        }
//        // Parsing all CallAccessExpr to add Tags for the constraint's skeleton
//        for (var symExpr : ArgOrReturnExprParseCandidates) {
//            parseCallAccessExpr(symExpr);
//        }
//
//        // merge constraints according to memory alias
//        mergeConstraints();
//
//        // Remove meaningLess constraints
//        removeRedundantConstraints();

        Logging.info("InterContext", "Collect constraints done.");
    }

    /**
     * Current memory alias graph is not complete, it only contains the alias relationship with explicit data-flow relations.
     * And alias relations introduced by memory alias is not handled yet.
     * For example: if `a` and `b` is alias, then `*(a + 0x10)` and `*(b + 0x10)` should be alias too.
     * In this method, we consider fields as type alias only if their bases are alias and offsets are the same.
     */
    // TODO: using workList algorithm to make type alias graph reach a fixed point, currently we only consider 1-layer memory alias.
    private void handleMemoryAlias() {
        var allBaseExprs = symExprManager.getAllBaseExprs();
        for (var baseExpr: allBaseExprs) {
            var fieldExprs = symExprManager.getFieldInfo(baseExpr);
            for (var fieldInfo: fieldExprs.entrySet()) {
                var offset = fieldInfo.getKey();
                var fieldAccessExprs = fieldInfo.getValue();
                var otherFieldExprsWithSameOffset = getOtherFieldExprsWithSameOffset(baseExpr, offset);
                for (var otherFieldExpr: otherFieldExprsWithSameOffset) {
                    for (var fieldAccessExpr: fieldAccessExprs) {
                        addTypeAliasRelation(fieldAccessExpr, otherFieldExpr, TypeAliasGraph.EdgeType.MEMALIAS);
                        Logging.debug("InterContext", String.format("Add memory alias relation between %s and %s", fieldAccessExpr, otherFieldExpr));
                    }
                }
            }
        }
    }


    private void mergeByTypeAliasGraph() {
        typeAliasManager.removeRedundantGraphs(collector.getAllExprs());

        for (var graph: typeAliasManager.getGraphs()) {
            if (graph.getNumNodes() > 1) {
                var mayTypeAgnosticParams = graph.findMayTypeAgnosticParams();
                if (!mayTypeAgnosticParams.isEmpty()) {
                    var confirmedTypeAgnositicParams = graph.checkTypeAgnosticParams(mayTypeAgnosticParams, collector.copy());
                    if (!confirmedTypeAgnositicParams.isEmpty()) {
                        Logging.info("Context", "Confirmed type agnostic params found: " + confirmedTypeAgnositicParams);
                        graph.removeTypeAgnosticCallEdgesAndMerge(confirmedTypeAgnositicParams, collector);
                    } else {
                        Logging.info("Context", "No confirmed type agnostic params found.");
                        graph.mergeNodesConstraints(graph.getNodes(), collector);
                    }
                } else {
                    graph.mergeNodesConstraints(graph.getNodes(), collector);
                }
            }
        }
    }


    /**
     * Sometimes one field may reference multiple constraints, For example:
     * If FuncA: *(a + 0x10) and FuncB: *(b + 0x10) has no direct data-flow relation,
     * but a and b has a direct data-flow relation, then Solver will create 2 constraints for a + 0x10 and b + 0x10
     * and these two constraints will be put into same offset when merging a and b.
     * However, we think these two constraints are actually the same type, so we should merge them here.
     */
    private void mergeConstraints() {
        var workList = new LinkedList<TypeConstraint>();
        var allConstraints = collector.getAllConstraints();
        for (var constraint : allConstraints) {
            if (hasMultiReferenceField(constraint)) {
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
        for (var entry : collector.getAllEntries().entrySet()) {
            var expr = entry.getKey();
            var constraint = entry.getValue();
            if (constraint.isInterested()) {
                finalResult.put(expr, constraint);
            } else {
                TypeConstraint.remove(constraint);
                Logging.warn("Context", String.format("Remove not interested %s -> Constraint_%s",
                        expr.toString(), constraint.getName()));
            }
        }

        collector.updateAllEntries(finalResult);
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

        Logging.info("InterContext", String.format("Parsing FieldAccess Expression %s, parentTypeConstraint: Constraint_%s, derefDepth: %d",
                expr, parentTypeConstraint != null ? parentTypeConstraint.getName() : "null", derefDepth));

        SymbolExpr base = null, offset = null, index = null, scale = null;
        long offsetValue;
        if (!expr.isDereference()) {
            Logging.error("InterContext", String.format("Current Expression %s is not a field access expression", expr));
            return;
        } else {
            if (expr.getNestedExpr().isDereference()) {
                base = expr.getNestedExpr();
                offsetValue = 0L;
            } else {
                base = expr.getNestedExpr().getBase();
                offset = expr.getNestedExpr().getOffset();
                index = expr.getNestedExpr().getIndex();
                scale = expr.getNestedExpr().getScale();

                if (offset != null) {
                    if (!offset.isConst()) {
                        Logging.warn("InterContext", String.format("Offset is not a constant: %s, Skipping...", expr));
                        return;
                    } else {
                        offsetValue = offset.getConstant();
                    }
                } else {
                    offsetValue = 0L;
                }
            }
        }

        var baseConstraint = symExprManager.getOrCreateConstraint(base);
        updateFieldAccessConstraint(baseConstraint, offsetValue, expr);
        symExprManager.addFieldRelation(base, offsetValue, expr);
        if (parentTypeConstraint != null) {
            updateReferenceConstraint(baseConstraint, offsetValue, parentTypeConstraint);
        }

        if (index != null && scale != null) {
            if (scale.isNoZeroConst()) {
                baseConstraint.setElementSize(scale.getConstant());
            }
        }

        // If base is still dereference expr, means base is a field with pointer type which points to a composite data type.
        if (base.isDereference()) {
            parseFieldAccessExpr(base, baseConstraint, derefDepth + 1);
        }
    }

    /**
     * Parse the Argument Access SymbolExpr and build the constraints for it.
     * @param expr the Expression to parse
     */
    private void parseCallAccessExpr(SymbolExpr expr) {
        if (expr == null) return;
        Logging.info("Context", String.format("Parsing CallAccessExpr %s", expr));

        var base = expr.getBase();
        var offset = expr.getOffset();
        // If the CallSite Arguments are Expressions like base + offset, For example
        // foo(a+0x10, *(a+0x10)+0x10), it's source code may be:
        // foo(&a.field, &(a->field1).field2) or foo(&a->field, ...)
        // which means there may exist a nested constraint.
        if (base != null && offset != null && expr.hasAttribute(SymbolExpr.Attribute.ARGUMENT) &&
                offset.isConst() && collector.hasConstraint(base)) {
            var constraint = collector.getConstraint(base);
            long offsetValue = offset.getConstant();
            Logging.info("Context", String.format("There may exist a nested constraint in %s: offset 0x%x", expr, offsetValue));
            updateNestedConstraint(expr, constraint, offsetValue, collector.getConstraint(expr));
        }

        // If the CallSite Arguments are dereference expressions, For example
        // foo(*(a+0x10)), it's source code may be:
        // foo(a->field)
        if (expr.isDereference()) {
            parseFieldAccessExpr(expr);
        }
    }

    private void updateNestedConstraint(SymbolExpr expr, TypeConstraint nester, long offsetValue, TypeConstraint nestee) {
        var ap = APs.getCallAccessPoints(expr);
        updateFieldAccessConstraint(nester, offsetValue, ap);
        nester.addNestTo(offsetValue, nestee);
        nester.addFieldAttr(offsetValue, TypeConstraint.Attribute.MAY_NESTED);
        nestee.addNestedBy(nester, offsetValue);
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
                Logging.info("Context", String.format("Constraint_%s has multiple referenceTo at 0x%x", constraint.shortUUID, entry.getKey()));
                boolean shouldMerge = checkOffsetSize(constraint, entry.getKey(), Global.currentProgram.getDefaultPointerSize());
                if (!shouldMerge) {
                    Logging.warn("Context", String.format("Constraint_%s has different size at 0x%x when handling multiReference.", constraint.shortUUID, entry.getKey()));
                    continue;
                }

                TypeConstraint newMergedConstraint = new TypeConstraint();
                Logging.debug("Context", String.format("Created new merged constraint: Constraint_%s", newMergedConstraint.shortUUID));
                var toMerge = new HashSet<>(entry.getValue());
                for (var ref : toMerge) {
                    Logging.debug("Context", String.format("Merging Constraint_%s to Constraint_%s", ref.shortUUID, newMergedConstraint.shortUUID));
                    newMergedConstraint.merge(ref);
                }

                if (hasMultiReferenceField(newMergedConstraint)) {
                    workList.add(newMergedConstraint);
                }

                // add the new merged constraint in the symExprToConstraints
                for (var symExpr: newMergedConstraint.getAssociatedExpr()) {
                    collector.updateConstraint(symExpr, newMergedConstraint);
                    Logging.info("Context", String.format("Set expr %s -> Constraint_%s", symExpr, newMergedConstraint.shortUUID));
                }
            }
        }
    }


    private Set<SymbolExpr> getOtherFieldExprsWithSameOffset(SymbolExpr baseExpr, long offset) {
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
                    result.add(node);
                    Logging.debug("InterContext", String.format("Found other field expr %s with offset 0x%x", node, offset));
                }
            }
        }

        return result;
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
