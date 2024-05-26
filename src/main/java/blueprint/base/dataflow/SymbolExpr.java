package blueprint.base.dataflow;

import blueprint.utils.Logging;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;

import java.util.Objects;

/**
 * SymbolExpr represents all expressions in program that can be represented as :
 *  <p> base + index * scale + offset </p>
 */
public class SymbolExpr {
    private SymbolExpr baseExpr = null;
    private SymbolExpr indexExpr = null;
    private SymbolExpr scaleExpr = null;
    private SymbolExpr offsetExpr = null;

    private HighSymbol rootSym = null;
    private long constant = 0;
    private boolean dereference = false;
    private boolean reference = false;
    private SymbolExpr nestedExpr = null;

    private Function function = null;
    private String prefix = null;

    private boolean isConst = false;
    private boolean isGlobal = false;

    public SymbolExpr(Builder builder) {
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

        if (this.dereference && this.nestedExpr == null) {
            throw new IllegalArgumentException("Dereference expression must have a nested expression.");
        }

        if (this.hasOffset() && this.dereference) {
            throw new IllegalArgumentException("Dereference expression cannot have offset.");
        }

        if (!isNoZeroConst()) {
            var rootSymbol = getRootSymExpr().getRootSymbol();
            if (!rootSymbol.isGlobal()) {
                this.function = rootSymbol.getHighFunction().getFunction();
                this.prefix = this.function.getName();
            } else {
                this.prefix = "Global";
                this.isGlobal = true;
            }
        } else {
            this.prefix = "Constant";
        }
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


    public SymbolExpr add(SymbolExpr other) {
        if (this.hasIndexScale() && other.hasIndexScale()) {
            Logging.error(String.format("[SymbolExpr] Unsupported add operation: %s + %s", this.getRepresentation(), other.getRepresentation()));
        }

        // ensure that the constant value is always on the right side of the expression
        if (this.isNoZeroConst() && !other.isNoZeroConst()) {
            return other.add(this);
        }
        // ensure that the index * scale is always on the right side of base
        if (this.hasIndexScale() && !this.hasBase()) {
            if (!other.isConst()) {
                return other.add(this);
            }
        }

        Builder builder = new Builder();
        if (this.isConst() && other.isConst()) {
            builder.constant(this.constant + other.constant);
        }
        else if (this.isRootSymExpr() || this.isDereference()) {
            if (other.hasIndexScale()) {
                builder.base(this).index(other.indexExpr).scale(other.scaleExpr).offset(other.offsetExpr);
            } else {
                builder.base(this).offset(other);
            }
        }
        else if (!this.hasBase() && this.hasIndexScale()) {
            if (this.hasOffset()) {
                builder.index(this.indexExpr).scale(this.scaleExpr).offset(this.offsetExpr.add(other));
            } else {
                builder.index(this.indexExpr).scale(this.scaleExpr).offset(other);
            }
        }

        else if (this.hasBase() && this.hasOffset() && !this.hasIndexScale()) {
            builder.base(this).offset(this.offsetExpr.add(other));
        }
        else if (this.hasBase() && this.hasIndexScale()) {
            if (this.hasOffset()) {
                builder.base(this).index(this.indexExpr).scale(this.scaleExpr).offset(this.offsetExpr.add(other));
            } else {
                builder.base(this).index(this.indexExpr).scale(this.scaleExpr).offset(other);
            }
        }
        else {
            Logging.error(String.format("[SymbolExpr] Unsupported add operation: %s + %s", this.getRepresentation(), other.getRepresentation()));
        }

        return builder.build();
    }


    // TODO: add Type alias, if nestedExpr is TypeAlias, then the dereference should also be TypeAlias
    public SymbolExpr dereference() {
        if (this.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot dereference a constant value.");
        }
        return new Builder().dereference(this).build();
    }

    public SymbolExpr reference() {
        if (this.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot reference a constant value.");
        }
        return new Builder().reference(this).build();
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

    @Override
    public int hashCode() {
        return Objects.hash(baseExpr, indexExpr, scaleExpr, offsetExpr, rootSym, constant, dereference, reference, nestedExpr);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SymbolExpr that)) return false;
        return constant == that.constant &&
                dereference == that.dereference &&
                reference == that.reference &&
                Objects.equals(baseExpr, that.baseExpr) &&
                Objects.equals(indexExpr, that.indexExpr) &&
                Objects.equals(scaleExpr, that.scaleExpr) &&
                Objects.equals(offsetExpr, that.offsetExpr) &&
                Objects.equals(rootSym, that.rootSym) &&
                Objects.equals(nestedExpr, that.nestedExpr);
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

        private Builder dereference(SymbolExpr nested) {
            this.dereference = true;
            this.nestedExpr = nested;
            return this;
        }

        private Builder reference(SymbolExpr nested) {
            this.reference = true;
            this.nestedExpr = nested;
            return this;
        }

        public SymbolExpr build() {
            if ((indexExpr != null && scaleExpr == null) || (indexExpr == null && scaleExpr != null)) {
                throw new IllegalArgumentException("indexExpr and scaleExpr must either both be null or both be non-null.");
            }
            return new SymbolExpr(this);
        }
    }
}