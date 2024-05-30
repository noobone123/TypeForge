package blueprint.base.dataflow;

import blueprint.utils.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;

import java.util.Objects;
import java.util.HashMap;
import java.util.Map;

/**
 * SymbolExpr represents all expressions in program that can be represented as :
 *  <p> base + index * scale + offset </p>
 */
public class SymbolExpr {
    public SymbolExpr baseExpr = null;
    public SymbolExpr indexExpr = null;
    public SymbolExpr scaleExpr = null;
    public SymbolExpr offsetExpr = null;

    public HighSymbol rootSym = null;
    public long constant = 0;
    public boolean dereference = false;
    public boolean reference = false;
    public SymbolExpr nestedExpr = null;

    public Function function = null;
    public String prefix = null;

    public boolean isConst = false;
    public boolean isGlobal = false;
    public Address globalAddr = null;

    private static final Map<Integer, SymbolExpr> cache = new HashMap<>();

    public SymbolExpr(Builder builder) {
        // Be careful, for global variables, the same global variable have different HighSymbol instances
        // in different functions.
        // TODO: what about Global variable's complex SymbolExpr?
        this.baseExpr = builder.baseExpr;
        this.indexExpr = builder.indexExpr;
        this.scaleExpr = builder.scaleExpr;
        this.offsetExpr = builder.offsetExpr;
        this.rootSym = builder.rootSym;
        this.constant = builder.constant;
        this.dereference = builder.dereference;
        this.reference = builder.reference;
        this.nestedExpr = builder.nestedExpr;
        this.isConst = builder.isConst;
        this.isGlobal = builder.isGlobal;
        this.globalAddr = builder.globalAddr;

        if (this.dereference && this.nestedExpr == null) {
            throw new IllegalArgumentException("Dereference expression must have a nested expression.");
        }

        if (this.hasOffset() && this.dereference) {
            throw new IllegalArgumentException("Dereference expression cannot have offset.");
        }

        if (isGlobal) {
            this.prefix = "Global";
        } else if (isConst()) {
            this.prefix = "Constant";
        } else {
            var rootSymbol = getRootSymExpr().getRootSymbol();
            this.function = rootSymbol.getHighFunction().getFunction();
            this.prefix = this.function.getName();
        }

        Logging.info("Created new SymbolExpr: " + this);
    }

    public SymbolExpr getBase() {
        return baseExpr;
    }

    public SymbolExpr getOffset() {
        return offsetExpr;
    }

    public SymbolExpr getIndex() {
        return indexExpr;
    }

    public SymbolExpr getScale() {
        return scaleExpr;
    }

    public SymbolExpr getBaseIndexScale() {
        if (baseExpr == null && indexExpr == null && scaleExpr == null) {
            return null;
        }
        return new Builder().base(baseExpr).index(indexExpr).scale(scaleExpr).build();
    }

    public long getConstant() {
        return constant;
    }

    public boolean hasOffset() {
        return offsetExpr != null;
    }

    public boolean hasBase() {
        return baseExpr != null;
    }

    public boolean hasIndexScale() {
        return indexExpr != null && scaleExpr != null;
    }

    public boolean isNoZeroConst() {
        return isConst && constant != 0;
    }

    public boolean isConst() {
        return isConst;
    }

    public boolean isRootSymExpr() {
        return baseExpr == null && indexExpr == null && scaleExpr == null && offsetExpr == null && rootSym != null && constant == 0;
    }

    public HighSymbol getRootSymbol() {
        return rootSym;
    }

    public boolean isDereference() {
        assert baseExpr == null && indexExpr == null && scaleExpr == null && offsetExpr == null && rootSym == null && constant == 0;
        return dereference;
    }

    public boolean isReference() {
        return reference;
    }

    public SymbolExpr getNestedExpr() {
        return nestedExpr;
    }

    public boolean isGlobal() {
        return isGlobal;
    }

    public SymbolExpr getRootSymExpr() {
        if (isRootSymExpr()) {
            return this;
        }
        else if (isDereference() && nestedExpr != null) {
            return nestedExpr.getRootSymExpr();
        }
        else if (isReference() && nestedExpr != null) {
            return nestedExpr.getRootSymExpr();
        }
        else if (baseExpr != null) {
            return baseExpr.getRootSymExpr();
        }
        else if (indexExpr != null) {
            return indexExpr.getRootSymExpr();
        }
        Logging.error(String.format("[SymbolExpr] Cannot find representative root SymExpr for %s", this));
        return null;
    }

    public String getRepresentation() {
        StringBuilder sb = new StringBuilder();
        if (baseExpr != null) {
            sb.append(baseExpr.getRepresentation());
        }
        if (baseExpr != null && indexExpr != null) {
            sb.append(" + ");
        }
        if (indexExpr != null) {
            sb.append(indexExpr.getRepresentation()).append(" * ").append(scaleExpr.getRepresentation());
        }
        if ((baseExpr != null || indexExpr != null) && offsetExpr != null) {
            sb.append(" + ");
        }
        if (offsetExpr != null) {
            sb.append(offsetExpr.getRepresentation());
        }
        if (rootSym != null) {
            sb.append(rootSym.getName());
        }
        if (constant != 0) {
            sb.append("0x").append(Long.toHexString(constant));
        }
        if (dereference) {
            sb.append(String.format("*(%s)", nestedExpr.getRepresentation()));
        }
        if (reference) {
            sb.append(String.format("&(%s)", nestedExpr.getRepresentation()));
        }
        return sb.toString();
    }

    // IMPORTANT: modified the equals and hashCode should be careful the cache mechanism in Builder
    @Override
    public int hashCode() {
        if (isGlobal) {
            return Objects.hash(globalAddr);
        }
        else {
            return Objects.hash(baseExpr, indexExpr, scaleExpr,
                    offsetExpr, rootSym, constant,
                    dereference, reference, nestedExpr,
                    isConst);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SymbolExpr that)) return false;
        if (isGlobal) {
            return Objects.equals(globalAddr, that.globalAddr);
        } else {
            return Objects.equals(baseExpr, that.baseExpr) &&
                    Objects.equals(indexExpr, that.indexExpr) &&
                    Objects.equals(scaleExpr, that.scaleExpr) &&
                    Objects.equals(offsetExpr, that.offsetExpr) &&
                    Objects.equals(rootSym, that.rootSym) &&
                    constant == that.constant &&
                    dereference == that.dereference &&
                    reference == that.reference &&
                    Objects.equals(nestedExpr, that.nestedExpr) &&
                    isConst == that.isConst;
        }
    }

    @Override
    public String toString() {
        return String.format("%s: %s", prefix, getRepresentation());
    }

    /**
     * Builder Pattern for creating SymbolExpr
     */
    public static class Builder {
        private SymbolExpr baseExpr = null;
        private SymbolExpr indexExpr = null;
        private SymbolExpr scaleExpr = null;
        private SymbolExpr offsetExpr = null;
        private HighSymbol rootSym = null;
        private long constant = 0;
        private boolean dereference = false;
        private boolean reference = false;
        private SymbolExpr nestedExpr = null;
        private boolean isConst = false;
        private boolean isGlobal = false;
        private Address globalAddr = null;

        public Builder base(SymbolExpr base) {
            this.baseExpr = base;
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
            return this;
        }

        public Builder reference(SymbolExpr nested) {
            this.reference = true;
            this.nestedExpr = nested;
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
            if (isGlobal) {
                hash = Objects.hash(globalAddr);
            } else {
                hash = Objects.hash(baseExpr, indexExpr, scaleExpr,
                        offsetExpr, rootSym, constant,
                        dereference, reference, nestedExpr,
                        isConst);
            }

            if (cache.containsKey(hash)) {
                return cache.get(hash);
            }

            SymbolExpr expr = new SymbolExpr(this);
            cache.put(hash, expr);
            return expr;
        }
    }
}