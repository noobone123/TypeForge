package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.constraints.ConstraintCollector;
import blueprint.base.dataflow.constraints.PrimitiveTypeDescriptor;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.base.dataflow.typeAlias.TypeAliasGraph;
import blueprint.base.dataflow.typeAlias.TypeAliasManager;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Global;
import blueprint.utils.HighSymbolHelper;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr;

import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.*;


/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 */
public class Context {

    public static class IntraContext {
        /** The candidate HighSymbols that need to collect data-flow facts */
        public final HashSet<HighSymbol> tracedSymbols;
        public final HashSet<Varnode> tracedVarnodes;

        /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
        public HashMap<Varnode, KSet<SymbolExpr>> dataFlowFacts;
        public HashSet<SymbolExpr> returnExprs;
        public int dataFlowFactKSize = 10;
        public Map<PcodeOp, FunctionNode> callsites;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
            this.returnExprs = new HashSet<>();
            this.callsites = new HashMap<>();
        }

        public void setReturnExpr(SymbolExpr expr) {
            this.returnExprs.add(expr);
        }

        public Set<SymbolExpr> getReturnExpr() {
            return this.returnExprs;
        }

        public void addCallSite(PcodeOp op, FunctionNode funcNode) {
            callsites.put(op, funcNode);
        }

        public Map<PcodeOp, FunctionNode> getCallSites() {
            return callsites;
        }
    }

    public CallGraph callGraph;
    /** The workList queue of the whole program */
    public Queue<FunctionNode> workList;
    /** The set of solved functions */
    public Set<FunctionNode> solvedFunc;

    public HashMap<FunctionNode, IntraContext> intraCtxMap;

    public AccessPoints APs;
    public TypeAliasManager<SymbolExpr> typeAliasManager;
    public Set<SymbolExpr> memAccessExprParseCandidates;
    public Set<SymbolExpr> callAccessExprParseCandidates;
    public Set<SymbolExpr> fieldExprParseCandidates;
    public ConstraintCollector collector;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.solvedFunc = new HashSet<>();
        this.intraCtxMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.typeAliasManager = new TypeAliasManager<>();
        this.memAccessExprParseCandidates = new HashSet<>();
        this.callAccessExprParseCandidates = new HashSet<>();
        this.fieldExprParseCandidates = new HashSet<>();
        this.collector = new ConstraintCollector();
    }

    public void createIntraContext(FunctionNode funcNode) {
        IntraContext intraCtx = new IntraContext();
        intraCtxMap.put(funcNode, intraCtx);
    }

    public IntraContext getIntraContext(FunctionNode funcNode) {
        return intraCtxMap.get(funcNode);
    }

    public void addTracedSymbol(FunctionNode funcNode, HighSymbol highSymbol) {
        IntraContext intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Context", "Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        intraCtx.tracedSymbols.add(highSymbol);
    }

    public void addTracedVarnode(FunctionNode funcNode, Varnode vn) {
        var tracedVns = intraCtxMap.get(funcNode).tracedVarnodes;
        if (tracedVns.add(vn)) {
            Logging.debug("Context", "Add traced varnode: " + vn);
        }
    }

    public void addMemExprToParse(SymbolExpr expr) {
        Logging.info("Context", "Add MemExpr to parse: " + expr.toString());
        memAccessExprParseCandidates.add(expr);
    }

    public void addCallExprToParse(SymbolExpr expr) {
        Logging.info("Context", "Add CallExpr to parse: " + expr.toString());
        callAccessExprParseCandidates.add(expr);
    }

    public void addFieldExprToParse(SymbolExpr expr) {
        Logging.info("Context", "Add FieldExpr to parse: " + expr.toString());
        fieldExprParseCandidates.add(expr);
    }

    /**
     * create a new SymbolExpr and add it to the dataFlowFacts
     * @param funcNode the current function node
     * @param vn the varnode which holds the dataflow fact
     * @param symbolExpr the new symbolExpr
     */
    public void addNewExprIntoDataFlowFacts(FunctionNode funcNode, Varnode vn, SymbolExpr symbolExpr) {
        var intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Context", "Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        var curDataFlowFact = intraCtx.dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(intraCtx.dataFlowFactKSize));

        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("Context", "New " + vn + " -> " + curDataFlowFact);
        }
        addTracedVarnode(funcNode, vn);
    }


    /**
     * Merge the dataflow facts from input to output
     * @param funcNode the current function node
     * @param input the input varnode
     * @param output the output varnode
     * @param isStrongUpdate if true, the output varnode's dataflow facts will be cleared before merging
     */
    public void mergeSymbolExpr(FunctionNode funcNode, Varnode input, Varnode output, boolean isStrongUpdate) {
        var intraCtx = intraCtxMap.get(funcNode);
        assert intraCtx != null;
        var dataFlowFacts = intraCtx.dataFlowFacts;
        var inputFacts = dataFlowFacts.get(input);

        if (inputFacts == null) {
            Logging.warn("Context", "Failed to get dataflow fact for " + input);
            return;
        }

        var outputFacts = dataFlowFacts.computeIfAbsent(output, k -> new KSet<>(intraCtx.dataFlowFactKSize));
        if (isStrongUpdate) {
            outputFacts.clear();
        }

        outputFacts.merge(inputFacts);
        addTracedVarnode(funcNode, output);
        Logging.debug("Context", "Merge " + output + " -> " + outputFacts);
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initIntraDataFlowFacts(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        // Update the interestedVn
        for (var symbol: intraCtx.tracedSymbols) {
            Logging.info("Context", "Candidate HighSymbol: " + symbol.getName());

            SymbolExpr expr;
            TypeConstraint constraint;
            var dataType = symbol.getDataType();
            if (symbol.isGlobal()) {
                expr = new SymbolExpr.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(symbol), symbol).build();
                expr.addAttribute(SymbolExpr.Attribute.GLOBAL);
                constraint = collector.getConstraint(expr);
            } else {
                expr = new SymbolExpr.Builder().rootSymbol(symbol).build();
                constraint = collector.getConstraint(expr);
            }

            if (dataType instanceof Pointer ptr) {
                var ptrEE = ptr.getDataType();
                if (ptrEE instanceof Array || ptrEE instanceof Structure || ptrEE instanceof Union) {
                    Logging.info("Context", "Found decompiler recovered Pointer, points to " + dataType.getName());
                    expr.addAttribute(SymbolExpr.Attribute.POINTER_TO_COMPOSITE);
                    dataType = ptrEE;
                }
            }

            if (dataType instanceof Array array) {
                Logging.info("Context", "Found decompiler recovered Array " + dataType.getName());
                expr.addAttribute(SymbolExpr.Attribute.ARRAY);
                expr.setVariableSize(array.getLength());
                constraint.setTotalSize(array.getLength());
                constraint.setElementSize(array.getElementLength());
            }
            else if (dataType instanceof Structure structure) {
                Logging.info("Context", "Found decompiler recovered Structure " + dataType.getName());
                expr.addAttribute(SymbolExpr.Attribute.STRUCT);
                expr.setVariableSize(structure.getLength());
                constraint.setTotalSize(structure.getLength());
                for (var field: structure.getComponents()) {
                    constraint.addField(field.getOffset(), new PrimitiveTypeDescriptor(field.getDataType()));
                }
            }
            else if (dataType instanceof Union union) {
                Logging.info("Context", "Found decompiler recovered Union " + dataType.getName());
                expr.addAttribute(SymbolExpr.Attribute.UNION);
                expr.setVariableSize(union.getLength());
                constraint.setTotalSize(union.getLength());
                for (var field: union.getComponents()) {
                    constraint.addField(field.getOffset(), new PrimitiveTypeDescriptor(field.getDataType()));
                }
            }

            // In some time, a HighSymbol may not have corresponding HighVariable due to some reasons:
            // 1. HighSymbol is not used in the function
            // 2. HighSymbol is used in the function, but ghidra's decompiler failed to find the HighVariable
            if (symbol.getHighVariable() == null) {
                Logging.warn("Context", funcNode.value.getName() + " -> HighSymbol: " + symbol.getName() + " has no HighVariable");
            } else {
                // Initialize the dataFlowFacts using the interested varnodes and add
                // all varnode instances of the HighVariable to the IntraContext's tracedVarnodes
                // TODO: this may cause flow-insensitive, ... we can improve it in the future
                for (var vn: symbol.getHighVariable().getInstances()) {
                    addTracedVarnode(funcNode, vn);
                    addNewExprIntoDataFlowFacts(funcNode, vn, expr);
                }
            }
        }
    }

    public boolean isTracedVn(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        return intraCtx.tracedVarnodes.contains(vn);
    }

    public KSet<SymbolExpr> getIntraDataFlowFacts(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        var res = intraCtx.dataFlowFacts.get(vn);
        if (res == null) {
            Logging.warn("Context", "Failed to get dataflow fact for " + vn);
            return null;
        }
        return res;
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
        // Parsing all MemAccessExpr first to build the constraint's skeleton
        for (var symExpr : memAccessExprParseCandidates) {
            parseMemAccessExpr(symExpr, null, 0);
        }
        removeRedundantConstraints();
        // merging
        mergeByTypeAliasGraph();

        // Parsing all FieldAccessExpr to refine the constraint's skeleton
        for (var symExpr : fieldExprParseCandidates) {
            parseFieldAccessExpr(symExpr);
        }
        // Parsing all CallAccessExpr to add Tags for the constraint's skeleton
        for (var symExpr : callAccessExprParseCandidates) {
            parseCallAccessExpr(symExpr);
        }

        // merge constraints according to memory alias
        mergeConstraints();

        // Remove meaningLess constraints
        removeRedundantConstraints();

        Logging.info("Context", "Collect constraints done.");
    }


    private void mergeByTypeAliasGraph() {
        typeAliasManager.removeRedundantGraphs(collector.getAllExprs());

        for (var graph: typeAliasManager.getGraphs()) {
            if (graph.getNumNodes() > 1) {
                var mayTypeAgnosticParams = graph.findMayTypeAgnosticParams();
                if (!mayTypeAgnosticParams.isEmpty()) {
                    var confirmedTypeAgnositicParams = graph.checkTypeAgnosticParams(mayTypeAgnosticParams, new HashMap<>(collector.getAllEntries()));
                    if (!confirmedTypeAgnositicParams.isEmpty()) {
                        Logging.info("Context", "Confirmed type agnostic params found: " + confirmedTypeAgnositicParams);
                        graph.removeTypeAgnosticCallEdgesAndMerge(confirmedTypeAgnositicParams, collector.getAllEntries());
                    } else {
                        Logging.info("Context", "No confirmed type agnostic params found.");
                        graph.mergeNodesConstraints(graph.getNodes(), collector.getAllEntries());
                    }
                } else {
                    graph.mergeNodesConstraints(graph.getNodes(), collector.getAllEntries());
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
     * Parse the Memory Access SymbolExpr and build the constraints for it.
     * For example: if there is a MemAccessExpr: *(a+0x8)=b, the MemAccessExpr is a+0x8
     * @param expr the Expression to parse
     * @param parentTypeConstraint if the expr is a recursive dereference, the parentTypeConstraint is the constraint of the parent expr
     * @param derefDepth the dereference depth of the expr
     */
    private void parseMemAccessExpr(SymbolExpr expr, TypeConstraint parentTypeConstraint, long derefDepth) {
        if (expr == null) return;

        Logging.info("Context", String.format("Parsing MemAccessExpr %s, parentTypeConstraint: Constraint_%s, derefDepth: %d", expr, parentTypeConstraint != null ? parentTypeConstraint.getName() : "null", derefDepth));

        var base = expr.getBase();
        var offset = expr.getOffset();
        var index = expr.getIndex();
        var scale = expr.getScale();
        long offsetValue = 0;

        // case: a or *(expr)
        if (expr.isRootSymExpr() || expr.isDereference()) {
            var constraint = collector.getConstraint(expr);

            updateMemAccessConstraint(expr, parentTypeConstraint, offsetValue, constraint);

            if (expr.isDereference()) {
                parseMemAccessExpr(expr.getNestedExpr(), constraint, derefDepth + 1);
            }
        }

        else if (base != null) {
            var constraint = collector.getConstraint(base);

            if (expr.hasOffset() && offset.isConst()) {
                offsetValue = offset.getConstant();
            }
            else if (expr.hasOffset() && !offset.isConst()) {
                Logging.warn("Context", String.format("Offset is not a constant: %s, Skipping...", expr));
                return;
            }

            updateMemAccessConstraint(expr, parentTypeConstraint, offsetValue, constraint);

            if (index != null && scale != null) {
                if (scale.isNoZeroConst()) {
                    constraint.setElementSize(scale.getConstant());
                }
            }
            if (base.isDereference()) {
                parseMemAccessExpr(base.getNestedExpr(), constraint, derefDepth + 1);
            }
        }

        else {
            Logging.warn("Context", String.format("Failed to parse MemAccessExpr %s", expr));
        }
    }

    /**
     * For example: if there is a MemAccessExpr: *(a + 0x8) = b, the FieldAccessExpr is *(a + 0x8).
     * We need to parse the FieldAccessExpr only when this FieldAccessExpr is a pointer which points to a composite data type.
     * @param expr the Expression to parse
     */
    private void parseFieldAccessExpr(SymbolExpr expr) {
        if (!expr.isDereference()) {
            return;
        }
        Logging.info("Context", String.format("Parsing FieldAccessExpr %s", expr));

        // If FieldAccessExpr is a pointer points to a composite data type,
        // this FieldAccessExpr should have aliases in TypeAliasGraph with composite data type.
        var aliasGraph = typeAliasManager.getTypeAliasGraph(expr);
        if (aliasGraph == null) {
            Logging.debug("Context", String.format("FieldAccessExpr %s has no type alias", expr));
            return;
        }

        boolean isFieldPointToComposite = false;
        for (var aliasExpr: aliasGraph.getNodes()) {
            if (collector.hasConstraint(aliasExpr) && collector.getConstraint(aliasExpr).isInterested()) {
                isFieldPointToComposite = true;
                break;
            }
        }

        if (isFieldPointToComposite) {
            Logging.debug("Context", String.format("FieldAccessExpr %s may points to composite data type", expr));
            parseMemAccessExpr(expr, null, 0);
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
    }

    private void updateMemAccessConstraint(SymbolExpr expr, TypeConstraint parentTypeConstraint, long offsetValue, TypeConstraint constraint) {
        if (parentTypeConstraint == null) {
            updateFieldAccess(constraint, offsetValue, APs.getMemoryAccessPoints(expr));
        } else {
            updateReferenceConstraint(constraint, offsetValue, parentTypeConstraint);
        }
    }

    private void updateReferenceConstraint(TypeConstraint referencer, long offsetValue, TypeConstraint referencee) {
        referencee.addReferencedBy(referencer, offsetValue);
        referencer.addReferenceTo(offsetValue, referencee);
    }

    private void updateNestedConstraint(SymbolExpr expr, TypeConstraint nester, long offsetValue, TypeConstraint nestee) {
        var ap = APs.getCallAccessPoints(expr);
        updateFieldAccess(nester, offsetValue, ap);
        nester.addNestTo(offsetValue, nestee);
        nester.addFieldAttr(offsetValue, TypeConstraint.Attribute.MAY_NESTED);
        nestee.addNestedBy(nester, offsetValue);
    }

    private void updateFieldAccess(TypeConstraint currentTC, long offsetValue, Set<AccessPoints.AP> APs) {
        if (APs == null) {
            return;
        }
        for (var ap: APs) {
            currentTC.addFieldAccess(offsetValue, ap);
        }
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
