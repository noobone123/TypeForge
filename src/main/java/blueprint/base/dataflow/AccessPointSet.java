package blueprint.base.dataflow;

import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.PcodeOp;

import java.util.HashSet;
import java.util.Set;

public class AccessPointSet {
    /**
     * AP records access of a SymbolExpr in Ghidra's Pcodes.
     * access type can be load, store or ...
     * an access always associates with a TypeDescriptor.
     */
    public static class AP {
        public final PcodeOp pcodeOp;
        public final SymbolExpr symExpr;
        public final TypeDescriptor type;
        public final boolean isLoad;

        public AP(PcodeOp pcodeOp, SymbolExpr symExpr, TypeDescriptor type, boolean isLoad) {
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


    Set<AP> apSet;

    public AccessPointSet() {
        apSet = new HashSet<>();
    }

    public void addAccessPoint(PcodeOp pcodeOp, SymbolExpr symExpr, TypeDescriptor type, boolean isLoad) {
        apSet.add(new AP(pcodeOp, symExpr, type, isLoad));
        if (isLoad) {
            Logging.info(String.format("[Load] Found load operation: %s -> %s", symExpr, type));
        } else {
            Logging.info(String.format("[Store] Found store operation: %s -> %s", symExpr, type));
        }
    }
}

