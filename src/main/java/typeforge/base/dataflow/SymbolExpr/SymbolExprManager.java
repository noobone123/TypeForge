package typeforge.base.dataflow.SymbolExpr;

import typeforge.base.dataflow.skeleton.TypeConstraint;
import typeforge.base.dataflow.solver.InterSolver;
import typeforge.base.dataflow.typeRelation.TypeRelationGraph;
import typeforge.utils.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

public class SymbolExprManager {

    Map<SymbolExpr, TypeConstraint> exprToConstraintBeforeMerge;
    Map<SymbolExpr, TreeMap<Long, Set<SymbolExpr>>> baseToFieldsMap;
    Map<SymbolExpr, SymbolExpr> fieldToBaseMap;
    Map<SymbolExpr.Attribute, Set<SymbolExpr>> attributeToExpr;
    InterSolver interCtx;
    Map<SymbolExpr, DataType> exprToDecompilerInferredType;

    // mem alias related fields
    public Map<SymbolExpr, Set<SymbolExpr>> fastMayMemAliasCache;

    public SymbolExprManager(InterSolver interCtx) {
        exprToConstraintBeforeMerge = new HashMap<>();

        baseToFieldsMap = new HashMap<>();
        fieldToBaseMap = new HashMap<>();
        attributeToExpr = new HashMap<>();
        this.interCtx = interCtx;

        exprToDecompilerInferredType = new HashMap<>();
        fastMayMemAliasCache = new HashMap<>();
    }

    /**
     * Get the fieldAccess Expressions by given baseExpression and offset value
     * @param base the base expression
     * @param offset the offset value
     * @return the fieldAccess Expressions
     */
    public Optional<Set<SymbolExpr>> getFieldExprsByOffset(SymbolExpr base, long offset) {
        if (baseToFieldsMap.containsKey(base)) {
            return Optional.ofNullable(baseToFieldsMap.get(base).get(offset));
        } else {
            return Optional.empty();
        }
    }

    /**
     * Update the SymbolExpr's field relationship
     */
    public void addFieldRelation(SymbolExpr base, long offset, SymbolExpr field) {
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
    public void addExprAttribute(SymbolExpr expr, SymbolExpr.Attribute attr) {
        expr.addAttribute(attr);
        attributeToExpr.computeIfAbsent(attr, k -> new HashSet<>()).add(expr);
    }

    public Set<SymbolExpr> getExprsByAttribute(SymbolExpr.Attribute attr) {
        return attributeToExpr.getOrDefault(attr, new HashSet<>());
    }

    /**
     * Create a TypeConstraint for the given expression
     * @param expr the expression to create constraint for
     */
    public TypeConstraint createConstraint(SymbolExpr expr) {
        TypeConstraint constraint = new TypeConstraint();
        exprToConstraintBeforeMerge.put(expr, constraint);
        Logging.debug("SymbolExprManager", String.format("Create TypeConstraint : %s -> %s", expr.getRepresentation(), constraint));
        return constraint;
    }

    /**
     * Get the TypeConstraint for the given expression
     * @param expr the expression to get constraint for
     * @return the TypeConstraint for the given expression
     */
    public TypeConstraint getConstraint(SymbolExpr expr) {
        if (exprToConstraintBeforeMerge.containsKey(expr)) {
            Logging.debug("SymbolExprManager", String.format("Get TypeConstraint : %s -> %s", expr, exprToConstraintBeforeMerge.get(expr)));
            return exprToConstraintBeforeMerge.get(expr);
        } else {
            Logging.debug("SymbolExprManager", String.format("No TypeConstraint found for %s", expr));
            return null;
        }
    }

    /**
     * Get or create a TypeConstraint for the given expression
     * @return the TypeConstraint for the given expression
     */
    public TypeConstraint getOrCreateConstraint(SymbolExpr expr) {
        var result = getConstraint(expr);
        if (result == null) {
            return createConstraint(expr);
        }
        return result;
    }

    public void addDecompilerInferredType(SymbolExpr expr, DataType dataType) {
        exprToDecompilerInferredType.put(expr, dataType);
    }

    public Optional<DataType> getInferredType(SymbolExpr expr) {
        return Optional.ofNullable(exprToDecompilerInferredType.get(expr));
    }

    /**
     * Get the mayMemAliases of the given expression
     * @param expr the expression to get mayMemAliases for
     * @return the mayMemAliases of the given expression
     */
    public Set<SymbolExpr> fastGetMayMemAliases(SymbolExpr expr) {
        // get from cache first
        if (fastMayMemAliasCache.containsKey(expr)) {
            Logging.debug("SymbolExprManager", String.format("Get MayMemAliases from cache: %s", expr));
            return fastMayMemAliasCache.get(expr);
        }

        var parseResult = ParsedExpr.parseFieldAccessExpr(expr);
        if (parseResult.isEmpty()) { return new HashSet<>(); }
        var parsedExpr = parseResult.get();
        var baseExpr = parsedExpr.base;
        var indexExpr = parsedExpr.index;
        var scaleExpr = parsedExpr.scale;
        var offset = parsedExpr.offsetValue;

        var mayAliasExpr = new HashSet<SymbolExpr>();

        var taG = interCtx.typeRelationManager.getTypeRelationGraph(baseExpr);
        if (taG == null) {
            return mayAliasExpr;
        }

        var paths = taG.pathManager.getAllPathContainsNode(baseExpr);
        if (paths == null) {
            Logging.warn("SymbolExprManager", String.format("No paths found for baseExpr %s in %s", baseExpr, taG));
            return mayAliasExpr;
        }
        if (paths.isEmpty()) {
            return mayAliasExpr;
        }

        Logging.info("SymbolExprManager",
                String.format("Found %d base expr %s 's paths for finding mayMemAlias for %s", paths.size(), baseExpr, expr));

        for (var path: paths) {
            for (var node: path.nodes) {
                var result = getFieldExprsByOffset((SymbolExpr) node, offset);
                if (result.isPresent()) {
                    mayAliasExpr.addAll(result.get());
                }
            }
        }

        // update cache
        for (var alias: mayAliasExpr) {
            fastMayMemAliasCache.put(alias, mayAliasExpr);
        }

        Logging.info("SymbolExprManager", String.format("Found MayMemAliases of %s: %s", expr, mayAliasExpr));
        return mayAliasExpr;
    }


    /**
     * Add operation on two SymbolExpr
     * @return the result of the add operation
     */
    public SymbolExpr add(SymbolExpr a, SymbolExpr b) {
        if (a.hasIndexScale() && b.hasIndexScale()) {
            Logging.error("SymbolExprManager", String.format("Unsupported add operation: %s + %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }

        // ensure that the constant value is always on the right side of the expression
        if (a.isNoZeroConst() && !b.isNoZeroConst()) {
            return add(b, a);
        }
        // ensure that the index * scale is always on the right side of base
        if (a.hasIndexScale() && !a.hasBase()) {
            if (!b.isConst()) {
                return add(b, a);
            }
        }

        Builder builder = new Builder();
        if (a.isConst() && b.isConst()) {
            builder.constant(a.constant + b.constant);
        }
        else if (a.isRootSymExpr() || a.isDereference() || a.isReference()) {
            if (b.hasIndexScale()) {
                // Set `base + index * scale` and `base` type alias
                interCtx.addTypeRelation(new Builder().base(a).index(b.indexExpr).scale(b.scaleExpr).build(), a, TypeRelationGraph.EdgeType.INDIRECT);
                builder.base(a).index(b.indexExpr).scale(b.scaleExpr).offset(b.offsetExpr);
                addExprAttribute(a, SymbolExpr.Attribute.MAY_ARRAY_PTR);
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
                addExprAttribute(a, SymbolExpr.Attribute.MAY_ARRAY_PTR);
            }
        }
        else {
            Logging.error("SymbolExpr", String.format("Unsupported add operation: %s + %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }
        return builder.build();
    }

    /**
     * Multiply operation on two SymbolExpr
     * @return the result of the multiply operation
     */
    public SymbolExpr multiply(SymbolExpr a, SymbolExpr b) {
        if (!a.isConst() && !b.isConst) {
            Logging.warn("SymbolExpr", String.format("Unsupported multiply operation: %s * %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }

        // ensure that the constant value is always on the right side of the expression
        if (a.isNoZeroConst() && !b.isNoZeroConst()) {
            return multiply(b, a);
        }

        Builder builder = new Builder();
        if (a.isConst() && b.isConst()) {
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
            Logging.warn("SymbolExpr", String.format("Unsupported multiply operation: %s * %s", a.getRepresentation(), b.getRepresentation()));
            return null;
        }

        return builder.build();
    }

    /**
     * Dereference operation on a SymbolExpr
     * @return the result of the dereference operation
     */
    public SymbolExpr dereference(SymbolExpr a) {
        if (a.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot dereference a constant value.");
        }
        var newExpr = new Builder().dereference(a).build();
        if (a.hasBase() && a.hasIndexScale() && !a.hasOffset()) {
            interCtx.addTypeRelation(newExpr, new Builder().dereference(a.baseExpr).build(), TypeRelationGraph.EdgeType.INDIRECT);
        }
        return newExpr;
    }

    /**
     * Reference operation on a SymbolExpr
     * @return the result of the reference operation
     */
    public SymbolExpr reference(SymbolExpr a) {
        if (a.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot reference a constant value.");
        }
        return new Builder().reference(a).build();
    }


    /**
     * Builder Pattern for creating SymbolExpr
     */
    public static class Builder {
        private static final Map<Integer, SymbolExpr> builderCache = new HashMap<>();
        private static final Map<String, SymbolExpr> exprStringToExpr = new HashMap<>();
        public SymbolExpr baseExpr = null;
        public SymbolExpr indexExpr = null;
        public SymbolExpr scaleExpr = null;
        public SymbolExpr offsetExpr = null;
        public HighSymbol rootSym = null;
        public long constant = 0;
        public boolean dereference = false;
        public boolean reference = false;
        public SymbolExpr nestedExpr = null;
        public boolean isConst = false;
        public boolean isGlobal = false;
        public Address globalAddr = null;
        public boolean isTemp = false;
        public Varnode temp = null;

        public Builder base(SymbolExpr base) {
            this.baseExpr = base;

            if (base.isGlobal) {
                this.isGlobal = true;
                this.globalAddr = base.globalAddr;
            }
            return this;
        }

        public Builder index(SymbolExpr index) {
            this.indexExpr = index;
            return this;
        }

        public Builder scale(SymbolExpr scale) {
            this.scaleExpr = scale;
            return this;
        }

        public Builder offset(SymbolExpr offset) {
            this.offsetExpr = offset;
            return this;
        }

        public Builder rootSymbol(HighSymbol symbol) {
            this.rootSym = symbol;
            return this;
        }

        public Builder constant(long constant) {
            this.isConst = true;
            this.constant = constant;
            return this;
        }

        public Builder dereference(SymbolExpr nested) {
            this.dereference = true;
            this.nestedExpr = nested;
            this.isGlobal = nested.isGlobal;
            this.globalAddr = nested.globalAddr;
            return this;
        }

        public Builder reference(SymbolExpr nested) {
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

        public SymbolExpr build() {
            if ((indexExpr != null && scaleExpr == null) || (indexExpr == null && scaleExpr != null)) {
                throw new IllegalArgumentException("indexExpr and scaleExpr must either both be null or both be non-null.");
            }


            int hash;
            // IMPORTANT: modified the equals and hashCode should be careful the cache mechanism in Builder
            if (isGlobal) {
                hash = Objects.hash(globalAddr, indexExpr, scaleExpr,
                        offsetExpr, constant, dereference, reference, nestedExpr);
            }
            else if (isTemp) {
                hash = Objects.hash(temp);
            }
            else {
                hash = Objects.hash(baseExpr, indexExpr, scaleExpr,
                        offsetExpr, rootSym, constant,
                        dereference, reference, nestedExpr,
                        isConst);
            }

            if (builderCache.containsKey(hash)) {
                return builderCache.get(hash);
            }

            SymbolExpr expr = new SymbolExpr(this);
            builderCache.put(hash, expr);
            exprStringToExpr.put(expr.toString(), expr);
            return expr;
        }
    }
}
