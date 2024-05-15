package blueprint.base.dataflow;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

import java.util.Objects;

public class SymbolExpr {
    public HighSymbol baseSymbol;
    public long offset;

    public SymbolExpr(HighSymbol base, long off) {
        this.baseSymbol = Objects.requireNonNull(base, "Base symbol must not be null");
        this.offset = off;
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
        return String.format("%s: %s + 0x%d", baseSymbol.getHighFunction().getFunction().getName(), baseSymbol.getName(), offset);
    }
}