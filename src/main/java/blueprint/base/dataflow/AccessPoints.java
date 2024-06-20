package blueprint.base.dataflow;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.PcodeOp;

import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Objects;
import java.util.Set;

public class AccessPoints {

    public enum AccessType {
        LOAD,
        STORE,
        ARGUMENT,
        RETURN_VALUE,
        INDIRECT
    }

    /**
     * AP records an access point of a symbolExpr
     * access type can be load, store or ...
     * an access point always associates with a TypeDescriptor.
     */
    public static class AP {
        public final PcodeOp pcodeOp;
        public final DataType dataType;

        /** accessType: including:
         * 0: load
         * 1: store
         * 2: argument
         * 3. RETURN_VALUE
         */
        public AccessType accessType;

        public AP(PcodeOp pcodeOp, DataType type, AccessType accessType) {
            this.pcodeOp = pcodeOp;
            if (accessType != AccessType.ARGUMENT) {
                assert type != null;
                this.dataType = type;
            }
            else {
                this.dataType = null;
            }
            this.accessType = accessType;
        }

        @Override
        public int hashCode() {
            return Objects.hash(pcodeOp, accessType);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof AP other) {
                if (accessType != AccessType.ARGUMENT) {
                    if (!pcodeOp.equals(other.pcodeOp)) return false;
                    return accessType == other.accessType;
                } else {
                    return pcodeOp.equals(other.pcodeOp) && accessType == other.accessType;
                }
            }
            return false;
        }
    }

    /**
     * Each SymbolExpr in function may be accessed by multiple PcodeOps with different types.
     * So we need to record all the access points of each SymbolExpr.
     */

    /** Expressions in memAccessMap: (param + 1) means there is a load/store into (param + 1), loaded value can be represented as *(param + 1) */
    private final Map<SymbolExpr, Set<AP>> fieldExprToAccessMap;
    /** Expressions in callAccessMap: (param + 1) means there is a callsite, using (param + 1) as an argument, or *(a + 1) as return value */
    private final Map<SymbolExpr, Set<AP>> argOrReturnExprToAccessMap;

    public AccessPoints() {
        fieldExprToAccessMap = new HashMap<>();
        argOrReturnExprToAccessMap = new HashMap<>();
    }

    public void addFieldAccessPoint(SymbolExpr symExpr, PcodeOp op, DataType type, AccessType accessType) {
        fieldExprToAccessMap.putIfAbsent(symExpr, new HashSet<>());
        fieldExprToAccessMap.get(symExpr).add(new AP(op, type, accessType));
        Logging.info("AccessPoints", String.format("Add Field Access %s for [%s] with type [%s]", accessType, symExpr, type.getName()));
    }

    public void addArgOrReturnAccessPoint(SymbolExpr symExpr, PcodeOp op, AccessType accessType) {
        argOrReturnExprToAccessMap.putIfAbsent(symExpr, new HashSet<>());
        argOrReturnExprToAccessMap.get(symExpr).add(new AP(op, null, accessType));
        Logging.info("AccessPoints", String.format("Add Argument/Return Access %s for [%s]", accessType, symExpr));
    }

    public Set<AP> getFieldAccessPoints(SymbolExpr symExpr) {
        return fieldExprToAccessMap.get(symExpr);
    }
}

