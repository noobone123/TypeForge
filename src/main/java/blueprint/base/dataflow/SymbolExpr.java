package blueprint.base.dataflow;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

import java.util.Objects;


/**
 * VarNode with data-flow traceable to base pointer.
 * For example, If there is a statement like following:
 * <p>
 *     <code> varnode_1 = *(varnode_0 + 4) </code>
 *     <code> varnode_2 = *(varnode_1 + 4) </code>
 * </p>
 *
 * varnode_0 is the original pointer, varnode_1's offset is 4, varnode_2's offset is 8
 */
public class SymbolExpr {
    public HighSymbol baseSymbol;
    public long offset;
    public Varnode representVn;
    public Varnode baseVn;

    public SymbolExpr(Varnode representVn, Varnode base, long off) {
        this.baseVn = base;
        this.baseSymbol = base.getHigh().getSymbol();
        if (this.baseSymbol == null) {
            Logging.warn("Base Varnode has no HighSymbol: " + base);
        }
        this.representVn = representVn;
        offset = off;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SymbolExpr that = (SymbolExpr) o;
        return offset == that.offset &&
                Objects.equals(baseSymbol, that.baseSymbol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(baseSymbol, offset);
    }

    @Override
    public String toString() {
        var representAST = (VarnodeAST) representVn;
        return "PointerRef{ " +
                "repr = " + representAST.getUniqueId() + "_" + representAST +  ", " +
                "symbol = " + baseSymbol.getName() + ", " +
                "offset = 0x" + Long.toHexString(offset) +
                " }";
    }
}