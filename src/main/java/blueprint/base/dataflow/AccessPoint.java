package blueprint.base.dataflow;

import blueprint.base.dataflow.constraints.TypeDescriptor;
import ghidra.program.model.pcode.PcodeOp;

/**
 * AccessPoint records access of a SymbolExpr in Ghidra's Pcodes.
 * access type can be load, store or ...
 * an access always associates with a TypeDescriptor.
 */
public class AccessPoint {
    public final PcodeOp pcodeOp;
    public final SymbolExpr symExpr;
    public final TypeDescriptor type;
    public final boolean isLoad;

    public AccessPoint(PcodeOp pcodeOp, SymbolExpr symExpr, TypeDescriptor type, boolean isLoad) {
        this.pcodeOp = pcodeOp;
        this.symExpr = symExpr;
        this.type = type;
        this.isLoad = isLoad;
    }

    @Override
    public String toString() {
        return String.format("%s -> %s", symExpr, type);
    }
}
