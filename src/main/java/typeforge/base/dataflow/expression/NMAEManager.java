package typeforge.base.dataflow.expression;

import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.node.CallSite;
import typeforge.utils.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

public class NMAEManager {

    Set<NMAE> fieldExprSet = new HashSet<>();

    /**
     * Before Path-Aware Type Hint Propagation. Each `NMAE` has a corresponding `Skeleton`
     * `Skeleton` is the partial constraint of the composite type pointed by the NMAE.
     * If there exist a stack-allocated variable, then its pointer should be represented as `&stack_variable`.
     */
    Map<NMAE, Skeleton> exprToSkeletonBeforeMerge;
    Map<NMAE, TreeMap<Long, Set<NMAE>>> baseToFieldsMap;
    Map<NMAE, NMAE> fieldToBaseMap;
    Map<NMAE.Attribute, Set<NMAE>> attributeToExpr;
    TFGManager graphManager;
    Map<NMAE, DataType> exprToDecompilerInferredType;

    // mem alias related fields
    public Map<NMAE, Set<NMAE>> fastMayMemAliasCache;

    public NMAEManager(TFGManager graphManager) {
        exprToSkeletonBeforeMerge = new HashMap<>();

        baseToFieldsMap = new HashMap<>();
        fieldToBaseMap = new HashMap<>();
        attributeToExpr = new HashMap<>();
        this.graphManager = graphManager;

        exprToDecompilerInferredType = new HashMap<>();
        fastMayMemAliasCache = new HashMap<>();
    }

    /**
     * Get the fieldAccess Expressions by given baseExpression and offset value
     * @param base the base expression
     * @param offset the offset value
     * @return the fieldAccess Expressions
     */
    public Optional<Set<NMAE>> getFieldExprsByOffset(NMAE base, long offset) {
        if (baseToFieldsMap.containsKey(base)) {
            return Optional.ofNullable(baseToFieldsMap.get(base).get(offset));
        } else {
            return Optional.empty();
        }
    }

    public void addFieldAccessExpr(NMAE fieldExpr) {
        fieldExprSet.add(fieldExpr);
    }

    public Set<NMAE> getFieldAccessExprSet() {
        return fieldExprSet;
    }

    /**
     * Update the SymbolExpr's field relationship.
     * Can also been seen as a member edge in TFG
     */
    public void addFieldRelation(NMAE base, long offset, NMAE field) {
        // fieldExprsMap's Value is a Set, because there may be multiple fieldsAccessExpr
        // For example:
        // a: { 0x8: [ *(a + 0x8), *(a + b * 0x10 + 0x8) ] }
        baseToFieldsMap.computeIfAbsent(base, k -> new TreeMap<>()).computeIfAbsent(offset, k -> new HashSet<>()).add(field);
        fieldToBaseMap.put(field, base);
    }

    /**
     * Add an attribute to the given expression
     * @param expr the expression to add attribute to
     * @param attr the attribute to add
     */
    public void addExprAttribute(NMAE expr, NMAE.Attribute attr) {
        expr.addAttribute(attr);
        attributeToExpr.computeIfAbsent(attr, k -> new HashSet<>()).add(expr);
    }

    public Set<NMAE> getExprsByAttribute(NMAE.Attribute attr) {
        return attributeToExpr.getOrDefault(attr, new HashSet<>());
    }

    public Map<NMAE, Skeleton> getExprToSkeletonBeforeMerge() {
        return exprToSkeletonBeforeMerge;
    }

    /**
     * Get or create a Skeleton for the given expression.
     * The created Skeleton will be auto associated with
     *  the expression in the `exprToSkeletonBeforeMerge` map.
     * @return the Skeleton for the given expression
     */
    public Skeleton getOrCreateSkeleton(NMAE expr) {
        var result = getSkeleton(expr);
        if (result == null) {
            return createSkeleton(expr);
        }
        return result;
    }

    /**
     * Create a Skeleton for the given expression
     * @param expr the expression to create Skeleton for
     */
    public Skeleton createSkeleton(NMAE expr) {
        Skeleton skt = new Skeleton();
        exprToSkeletonBeforeMerge.put(expr, skt);
        Logging.trace("NMAEManager", String.format("Create Skeleton : %s -> %s", expr.getRepresentation(), skt));
        return skt;
    }

    /**
     * Get the Skeleton for the given expression
     * @param expr the expression to get Skeleton for
     * @return the Skeleton for the given expression
     */
    public Skeleton getSkeleton(NMAE expr) {
        if (exprToSkeletonBeforeMerge.containsKey(expr)) {
            Logging.trace("NMAEManager", String.format("Get Skeleton : %s -> %s", expr, exprToSkeletonBeforeMerge.get(expr)));
            return exprToSkeletonBeforeMerge.get(expr);
        } else {
            Logging.trace("NMAEManager", String.format("No Skeleton found for %s", expr));
            return null;
        }
    }

    /**
     * Get the mayMemAliases of the given expression
     * @param expr the expression to get mayMemAliases for
     * @return the mayMemAliases of the given expression
     */
//    public Set<NMAE> fastGetMayMemAliases(NMAE expr) {
//        // get from cache first
//        if (fastMayMemAliasCache.containsKey(expr)) {
//            Logging.trace("NMAEManager", String.format("Get MayMemAliases from cache: %s", expr));
//            return fastMayMemAliasCache.get(expr);
//        }
//
//        var parseResult = ParsedExpr.parseFieldAccessExpr(expr);
//        if (parseResult.isEmpty()) { return new HashSet<>(); }
//        var parsedExpr = parseResult.get();
//        var baseExpr = parsedExpr.base;
//        var indexExpr = parsedExpr.index;
//        var scaleExpr = parsedExpr.scale;
//        var offset = parsedExpr.offsetValue;
//
//        var mayAliasExpr = new HashSet<NMAE>();
//
//        var taG = graphManager.getTFG(baseExpr);
//        if (taG == null) {
//            return mayAliasExpr;
//        }
//
//        var paths = taG.pathManager.getAllPathContainsNode(baseExpr);
//        if (paths == null) {
//            Logging.warn("NMAEManager", String.format("No paths found for baseExpr %s in %s", baseExpr, taG));
//            return mayAliasExpr;
//        }
//        if (paths.isEmpty()) {
//            return mayAliasExpr;
//        }
//
//        Logging.debug("NMAEManager",
//                String.format("Found %d base expr %s 's paths for finding mayMemAlias for %s", paths.size(), baseExpr, expr));
//
//        for (var path: paths) {
//            for (var node: path.nodes) {
//                var result = getFieldExprsByOffset((NMAE) node, offset);
//                if (result.isPresent()) {
//                    mayAliasExpr.addAll(result.get());
//                }
//            }
//        }
//
//        // update cache
//        for (var alias: mayAliasExpr) {
//            fastMayMemAliasCache.put(alias, mayAliasExpr);
//        }
//
//        Logging.debug("NMAEManager", String.format("Found MayMemAliases of %s: %s", expr, mayAliasExpr));
//        return mayAliasExpr;
//    }


    /**
     * Add operation on two SymbolExpr
     * @return the result of the add operation
     */
    public NMAE add(NMAE a, NMAE b) {
        if (a.hasIndexScale() && b.hasIndexScale()) {
            Logging.error("NMAEManager", String.format("Unsupported add operation: %s + %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }

        // ensure that the constant value is always on the right side of the expression
        if (a.isNoZeroConst() && !b.isNoZeroConst()) {
            return add(b, a);
        }
        // ensure that the index * scale is always on the right side of base
        if (a.hasIndexScale() && !a.hasBase()) {
            if (!b.isNormalConst()) {
                return add(b, a);
            }
        }

        Builder builder = new Builder();
        if (a.isNormalConst() && b.isNormalConst()) {
            builder.constant(a.constant + b.constant);
        }
        else if (a.isRootSymExpr() || a.isDereference() || a.isReference()) {
            if (b.hasIndexScale()) {
                // Set `base + index * scale` and `base` type alias
                graphManager.addEdge(new Builder().base(a).index(b.indexExpr).scale(b.scaleExpr).build(),
                        a,
                        TypeFlowGraph.EdgeType.ALIAS);
                builder.base(a).index(b.indexExpr).scale(b.scaleExpr).offset(b.offsetExpr);
                addExprAttribute(a, NMAE.Attribute.MAY_ARRAY_PTR);
            } else {
                builder.base(a).offset(b);
            }
        }
        else if (!a.hasBase() && a.hasIndexScale()) {
            if (a.hasOffset()) {
                builder.index(a.indexExpr).scale(a.scaleExpr).offset(add(a.offsetExpr, b));
            } else {
                builder.index(a.indexExpr).scale(a.scaleExpr).offset(b);
            }
        }

        else if (a.hasBase() && a.hasOffset() && !a.hasIndexScale()) {
            builder.base(a.baseExpr).offset(add(a.offsetExpr, b));
        }
        else if (a.hasBase() && a.hasIndexScale()) {
            if (a.hasOffset()) {
                builder.base(a.baseExpr).index(a.indexExpr).scale(a.scaleExpr).offset(add(a.offsetExpr, b));
            } else {
                builder.base(a.baseExpr).index(a.indexExpr).scale(a.scaleExpr).offset(b);
                addExprAttribute(a, NMAE.Attribute.MAY_ARRAY_PTR);
            }
        }
        else {
            Logging.error("NMAEManager", String.format("Unsupported add operation: %s + %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }
        return builder.build();
    }

    /**
     * Multiply operation on two SymbolExpr
     * @return the result of the multiply operation
     */
    public NMAE multiply(NMAE a, NMAE b) {
        if (!a.isNormalConst() && !b.isNormalConst()) {
            Logging.warn("NMAEManager", String.format("Unsupported multiply operation: %s * %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }

        // ensure that the constant value is always on the right side of the expression
        if (a.isNoZeroConst() && !b.isNoZeroConst()) {
            return multiply(b, a);
        }

        Builder builder = new Builder();
        if (a.isNormalConst() && b.isNormalConst()) {
            builder.constant(a.constant * b.constant);
        }
        else if (a.isRootSymExpr() || a.isDereference() || a.isReference()) {
            builder.index(a).scale(b);
        }
        else if (!a.hasBase() && a.hasIndexScale() && !a.hasOffset()) {
            builder.index(a.indexExpr).scale(multiply(a.scaleExpr, b));
        }
        else if (a.hasBase() && a.hasOffset() && !a.hasIndexScale()) {
            builder.index(a).scale(b);
        }
        else {
            Logging.warn("NMAEManager", String.format("Unsupported multiply operation: %s * %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }

        return builder.build();
    }

    /**
     * Dereference operation on a SymbolExpr
     * @return the result of the dereference operation
     */
    public NMAE dereference(NMAE a) {
        if (a.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot dereference a constant value.");
        }
        var newExpr = new Builder().dereference(a).build();
        if (a.hasBase() && a.hasIndexScale() && !a.hasOffset()) {
            graphManager.addEdge(newExpr,
                    new Builder().dereference(a.baseExpr).build(),
                    TypeFlowGraph.EdgeType.ALIAS);
        }
        return newExpr;
    }

    /**
     * Reference operation on a SymbolExpr
     * @return the result of the reference operation
     */
    public NMAE reference(NMAE a) {
        if (a.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot reference a constant value.");
        }
        return new Builder().reference(a).build();
    }

    /**
     * Builder Pattern for creating SymbolExpr
     */
    public static class Builder {
        private static final Map<Integer, NMAE> builderCache = new HashMap<>();
        private static final Map<String, NMAE> exprStringToExpr = new HashMap<>();
        public NMAE baseExpr = null;
        public NMAE indexExpr = null;
        public NMAE scaleExpr = null;
        public NMAE offsetExpr = null;
        public HighSymbol rootSym = null;
        public long constant = 0;
        public CallSite callSite = null;
        public int argIndex = -1;
        public boolean dereference = false;
        public boolean reference = false;
        public NMAE nestedExpr = null;
        public boolean isNormalConst = false;
        public boolean isArgConst = false;
        public boolean isGlobal = false;
        public Address globalAddr = null;
        public boolean isTemp = false;
        public Varnode temp = null;

        public Builder base(NMAE base) {
            this.baseExpr = base;

            if (base.isGlobal) {
                this.isGlobal = true;
                this.globalAddr = base.globalAddr;
            }
            return this;
        }

        public Builder index(NMAE index) {
            this.indexExpr = index;
            return this;
        }

        public Builder scale(NMAE scale) {
            this.scaleExpr = scale;
            return this;
        }

        public Builder offset(NMAE offset) {
            this.offsetExpr = offset;
            return this;
        }

        public Builder rootSymbol(HighSymbol symbol) {
            this.rootSym = symbol;
            return this;
        }

        public Builder constant(long constant) {
            this.isNormalConst = true;
            this.constant = constant;
            return this;
        }

        public Builder constArg(long constant, CallSite callSite, int index) {
            this.isArgConst = true;
            this.constant = constant;
            this.callSite = callSite;
            this.argIndex = index;
            return this;
        }

        public Builder dereference(NMAE nested) {
            this.dereference = true;
            this.nestedExpr = nested;
            this.isGlobal = nested.isGlobal;
            this.globalAddr = nested.globalAddr;
            return this;
        }

        public Builder reference(NMAE nested) {
            this.reference = true;
            this.nestedExpr = nested;
            this.isGlobal = nested.isGlobal;
            this.globalAddr = nested.globalAddr;
            return this;
        }

        public Builder global(Address globalAddr, HighSymbol symbol) {
            this.isGlobal = true;
            this.globalAddr = globalAddr;
            this.rootSymbol(symbol);
            return this;
        }

        public NMAE build() {
            if ((indexExpr != null && scaleExpr == null) || (indexExpr == null && scaleExpr != null)) {
                throw new IllegalArgumentException("indexExpr and scaleExpr must either both be null or both be non-null.");
            }


            int hash;
            // IMPORTANT: Following Hash Calculation should ba consistent with the `hash` function in `NMAE` class
            if (isGlobal) {
                hash = Objects.hash(globalAddr, indexExpr, scaleExpr,
                        offsetExpr, constant, dereference, reference, nestedExpr);
            }
            else if (isTemp) {
                hash = Objects.hash(temp);
            }
            else {
                hash = Objects.hash(baseExpr, indexExpr, scaleExpr,
                        offsetExpr, rootSym, constant, callSite, argIndex,
                        dereference, reference, nestedExpr,
                        isNormalConst, isArgConst);
            }

            if (builderCache.containsKey(hash)) {
                return builderCache.get(hash);
            }

            NMAE expr = new NMAE(this);
            builderCache.put(hash, expr);
            exprStringToExpr.put(expr.toString(), expr);
            return expr;
        }
    }
}
