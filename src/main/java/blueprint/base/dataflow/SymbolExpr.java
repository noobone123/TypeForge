package blueprint.base.dataflow;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;

import java.util.Objects;

public class SymbolExpr {
    private final HighSymbol baseSymbol;
    /** The offset of the outermost expression */
    private final long offset;

    /** a, a+10, a+20 has no nestedExpr, but *a, *(a+10), *(a+10)+0x10 has nestedExpr,
     * 1. *a: nestedExpr = a, offset = 0
     * 2. *(a+10): nestedExpr = a + 10, offset = 0
     * 3. *(a+10)+0x10: nestedExpr = a + 10, offset = 0x10
     */
    private final SymbolExpr nestedExpr;
    private final boolean dereference;

    public SymbolExpr(HighSymbol base, long offset) {
        this.baseSymbol = Objects.requireNonNull(base, "Base symbol must not be null");
        this.offset = offset;
        this.dereference = false;
        this.nestedExpr = null;
    }

    public SymbolExpr(SymbolExpr nestedExpr, boolean ifDeref) {
        this.baseSymbol = null;
        this.offset = 0;
        this.dereference = ifDeref;
        this.nestedExpr = nestedExpr;
    }

    public SymbolExpr(SymbolExpr nestedExpr, long offset) {
        if (nestedExpr.getOffset() == 0) {
            this.baseSymbol = null;
            this.offset = offset;
            this.dereference = false;
            this.nestedExpr = nestedExpr;
        } else {
            this.baseSymbol = null;
            this.offset = nestedExpr.getOffset() + offset;
            this.nestedExpr = nestedExpr.getNestedExpr();
            this.dereference = false;
        }
    }

    public HighSymbol getBaseSymbol() {
        if (baseSymbol != null && nestedExpr == null) {
            return baseSymbol;
        } else if (nestedExpr != null) {
            return nestedExpr.getBaseSymbol();
        } else {
            Logging.error("[SymExpr] No base symbol found");
            return null;
        }
    }

    public long getOffset() {
        return offset;
    }

    public SymbolExpr getNestedExpr() {
        return nestedExpr;
    }

    public boolean isNested() {
        return nestedExpr != null;
    }

    public String getRepresentation() {
        if (baseSymbol != null && nestedExpr == null) {
            // No nestedExpr means no dereference
            if (offset == 0) {
                return baseSymbol.getName();
            } else {
                return String.format("%s + 0x%s", baseSymbol.getName(), Long.toHexString(offset));
            }
        } else if (baseSymbol == null && nestedExpr != null) {
            StringBuilder sb = new StringBuilder();
            if (dereference) {
                sb.append("*");
            }
            if (offset == 0) {
                sb.append(String.format("(%s)", nestedExpr.getRepresentation()));
            } else {
                sb.append(String.format("%s + 0x%s", nestedExpr.getRepresentation(), Long.toHexString(offset)));
            }
            return sb.toString();
        } else {
            Logging.error("[SymExpr] No Representation found");
            return null;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SymbolExpr that = (SymbolExpr) o;
        return offset == that.offset &&
                Objects.equals(baseSymbol, that.baseSymbol) &&
                dereference == that.dereference &&
                Objects.equals(nestedExpr, that.nestedExpr);
    }

    @Override
    public int hashCode() {
        return Objects.hash(baseSymbol, offset, dereference, nestedExpr);
    }

    @Override
    public String toString() {
        return String.format("%s: %s", this.getBaseSymbol().getHighFunction().getFunction().getName(), getRepresentation());
    }
}