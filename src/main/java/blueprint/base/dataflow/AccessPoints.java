package blueprint.base.dataflow;

import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.PcodeOp;

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class AccessPoints {

    public enum AccessType {
        LOAD,
        STORE,
        ARGUMENT
    }

    /**
     * AP records an access point of a symbolExpr
     * access type can be load, store or ...
     * an access point always associates with a TypeDescriptor.
     */
    public static class AP {
        public final PcodeOp pcodeOp;
        public final TypeDescriptor dataType;

        /** accessType: including:
         * 0: load
         * 1: store
         * 2: argument
         */
        public AccessType accessType;

        public AP(PcodeOp pcodeOp, TypeDescriptor type, AccessType accessType) {
            this.pcodeOp = pcodeOp;
            this.dataType = type;
            this.accessType = accessType;
        }

        @Override
        public int hashCode() {
            return Objects.hash(pcodeOp, dataType, accessType);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof AP other) {
                return this.pcodeOp.equals(other.pcodeOp) && this.dataType.equals(other.dataType) && this.accessType == other.accessType;
            }
            return false;
        }
    }

    /**
     * Each SymbolExpr in function may be accessed by multiple PcodeOps with different types.
     * So we need to record all the access points of each SymbolExpr.
     */
    private final Map<SymbolExpr, Set<AP>> symExprToAPSet;

    public AccessPoints() {
        symExprToAPSet = new java.util.HashMap<>();
    }

    public Set<AP> getAccessPoints(SymbolExpr symExpr) {
        return symExprToAPSet.get(symExpr);
    }

    public void addAccessPoint(SymbolExpr symExpr, PcodeOp op, TypeDescriptor type, AccessType accessType) {
        symExprToAPSet.putIfAbsent(symExpr, new HashSet<>());
        symExprToAPSet.get(symExpr).add(new AP(op, type, accessType));
        Logging.info(String.format("[AP] Add %s access point for [%s] with type [%s]", accessType, symExpr, type != null ? type.getName() : "null"));
    }

    public Set<SymbolExpr> getSymbolExprs() {
        return symExprToAPSet.keySet();
    }
}

