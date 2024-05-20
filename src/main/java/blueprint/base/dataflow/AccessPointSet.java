package blueprint.base.dataflow;

import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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


    private final Set<AP> apSet;

    public AccessPointSet() {
        apSet = new HashSet<>();
    }

    public Set<AP> getAccessPoints() {
        return apSet;
    }

    public void addAccessPoint(PcodeOp pcodeOp, SymbolExpr symExpr, TypeDescriptor type, boolean isLoad) {
        apSet.add(new AP(pcodeOp, symExpr, type, isLoad));
        if (isLoad) {
            Logging.info(String.format("[Load] Found load operation: %s -> %s", symExpr, type));
        } else {
            Logging.info(String.format("[Store] Found store operation: %s -> %s", symExpr, type));
        }
    }

    public Map<SymbolExpr, Set<AP>> groupByRepresentativeRootSymbol() {
        return apSet.stream()
                .collect(
                        Collectors.groupingBy(
                                ap -> ap.symExpr.getRootSymExpr(),
                                Collectors.toSet()
                        ));
    }
}

