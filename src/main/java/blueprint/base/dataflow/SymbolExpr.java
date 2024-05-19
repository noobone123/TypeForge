package blueprint.base.dataflow;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;

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
    private SymbolExpr nestedExpr = null;

    public SymbolExpr(Builder builder) {
        this.baseExpr = builder.baseExpr;
        this.indexExpr = builder.indexExpr;
        this.scaleExpr = builder.scaleExpr;
        this.offsetExpr = builder.offsetExpr;
        this.rootSym = builder.rootSym;
        this.constant = builder.constant;
        this.dereference = builder.dereference;
        this.nestedExpr = builder.nestedExpr;
    }

    public SymbolExpr getBase() {
        return baseExpr;
    }

    public SymbolExpr getIndex() {
        return indexExpr;
    }

    public SymbolExpr getScale() {
        return scaleExpr;
    }

    public SymbolExpr getOffset() {
        return offsetExpr;
    }

    public boolean hasOffset() {
        return offsetExpr != null;
    }

    public boolean isConstant() {
        return constant != 0;
    }

    public SymbolExpr add(SymbolExpr other) {
        Builder builder = new Builder();

        // Base Expressions
        if (this.baseExpr != null || other.baseExpr != null) {
            builder.base(new SymbolExpr.Builder()
                    .base(this.baseExpr != null ? this.baseExpr : other.baseExpr)
                    .build());
        }

        // Index Expressions
        if (this.indexExpr != null || other.indexExpr != null) {
            if (this.indexExpr != null && other.indexExpr != null) {
                // handle case when both have index expressions
                builder.index(new SymbolExpr.Builder()
                        .index(this.indexExpr)
                        .scale(this.scaleExpr)
                        .build());
            } else {
                builder.index(this.indexExpr != null ? this.indexExpr : other.indexExpr);
                builder.scale(this.scaleExpr != null ? this.scaleExpr : other.scaleExpr);
            }
        }

        // Offset Expressions
        if (this.offsetExpr != null || other.offsetExpr != null) {
            if (this.offsetExpr != null && other.offsetExpr != null) {
                // Combine offsets recursively
                builder.offset(this.offsetExpr.add(other.offsetExpr));
            } else {
                builder.offset(this.offsetExpr != null ? this.offsetExpr : other.offsetExpr);
            }
        }

        // Aggregate constants
        long newConstant = this.constant + other.constant;
        builder.constant(newConstant);

        // Aggregate root symbol
        builder.rootSymbol(this.rootSym != null ? this.rootSym : other.rootSym);

        return builder.build();
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
        private SymbolExpr nestedExpr = null;

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
            this.constant = constant;
            return this;
        }

        public Builder dereference(SymbolExpr nested) {
            this.dereference = true;
            this.nestedExpr = nested;
            return this;
        }

        public Builder other(SymbolExpr other) {
            this.baseExpr = other.baseExpr;
            this.indexExpr = other.indexExpr;
            this.scaleExpr = other.scaleExpr;
            this.offsetExpr = other.offsetExpr;
            this.rootSym = other.rootSym;
            this.constant = other.constant;
            this.dereference = other.dereference;
            this.nestedExpr = other.nestedExpr;
            return this;
        }

        public SymbolExpr build() {
            if ((indexExpr != null && scaleExpr == null) || (indexExpr == null && scaleExpr != null)) {
                throw new IllegalArgumentException("indexExpr and scaleExpr must either both be null or both be non-null.");
            }
            return new SymbolExpr(this);
        }
    }

    public String getRepresentation() {
        StringBuilder sb = new StringBuilder();
        if (baseExpr != null) {
            sb.append(baseExpr.getRepresentation());
        }
        if (indexExpr != null) {
            sb.append(" + ").append(indexExpr.getRepresentation()).append(" * ").append(scaleExpr.getRepresentation());
        }
        if (offsetExpr != null) {
            sb.append(" + ").append(offsetExpr.getRepresentation());
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
        return sb.toString();
    }

    @Override
    public int hashCode() {
        return Objects.hash(baseExpr, indexExpr, scaleExpr, offsetExpr, rootSym, constant, dereference, nestedExpr);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SymbolExpr that)) return false;
        return constant == that.constant &&
                dereference == that.dereference &&
                Objects.equals(baseExpr, that.baseExpr) &&
                Objects.equals(indexExpr, that.indexExpr) &&
                Objects.equals(scaleExpr, that.scaleExpr) &&
                Objects.equals(offsetExpr, that.offsetExpr) &&
                Objects.equals(rootSym, that.rootSym) &&
                Objects.equals(nestedExpr, that.nestedExpr);
    }

    @Override
    public String toString() {
        return String.format("%s", getRepresentation());
    }
}