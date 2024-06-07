package blueprint.base.dataflow;

import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.utils.Logging;
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
        public final TypeDescriptor dataType;

        /** accessType: including:
         * 0: load
         * 1: store
         * 2: argument
         * 3. RETURN_VALUE
         */
        public AccessType accessType;

        public AP(PcodeOp pcodeOp, TypeDescriptor type, AccessType accessType) {
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
            return Objects.hash(pcodeOp, dataType, accessType);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof AP other) {
                if (accessType != AccessType.ARGUMENT) {
                    if (!pcodeOp.equals(other.pcodeOp)) return false;
                    assert dataType != null;
                    return dataType.equals(other.dataType) && accessType == other.accessType;
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
    private final Map<SymbolExpr, Set<AP>> memoryAccessMap;
    /** Expressions in callAccessMap: (param + 1) means there is a callsite, using (param + 1) as an argument, or *(a + 1) as return value */
    private final Map<SymbolExpr, Set<AP>> callAccessMap;

    public AccessPoints() {
        memoryAccessMap = new HashMap<>();
        callAccessMap = new HashMap<>();
    }

    public void addMemAccessPoint(SymbolExpr symExpr, PcodeOp op, TypeDescriptor type, AccessType accessType) {
        memoryAccessMap.putIfAbsent(symExpr, new HashSet<>());
        memoryAccessMap.get(symExpr).add(new AP(op, type, accessType));
        Logging.info("AccessPoints", String.format("Add MemAccess %s for [%s] with type [%s]", accessType, symExpr, type.getName()));
    }

    public void addCallAccessPoint(SymbolExpr symExpr, PcodeOp op, AccessType accessType) {
        callAccessMap.putIfAbsent(symExpr, new HashSet<>());
        callAccessMap.get(symExpr).add(new AP(op, null, accessType));
        Logging.info("AccessPoints", String.format("Add CallAccess %s for [%s]", accessType, symExpr));
    }

    public Set<AP> getMemoryAccessPoints(SymbolExpr symExpr) {
        return memoryAccessMap.get(symExpr);
    }

    public Set<AP> getCallAccessPoints(SymbolExpr symExpr) {
        return callAccessMap.get(symExpr);
    }

    public Set<SymbolExpr> getAllMemAccessExprs() {
        return memoryAccessMap.keySet();
    }

    public Set<SymbolExpr> getAllCallAccessExprs() {
        return callAccessMap.keySet();
    }

    public Set<SymbolExpr> getAllAccessExprs() {
        Set<SymbolExpr> allAccessExprs = new HashSet<>(memoryAccessMap.keySet());
        allAccessExprs.addAll(callAccessMap.keySet());
        return allAccessExprs;
    }

    /**
     * For all Expressions in callAccessMap, some of them is not considered as Composite DataType, so we need to remove
     * these redundant expressions by checking if their alias Expr has memory access.
     * @param typeAlias the alias of all expressions
     */
    public void removeRedundantCallAPs(UnionFind<SymbolExpr> typeAlias) {
        callAccessMap.keySet().removeIf(symExpr -> {
            boolean isRedundant = true;
            for (var alias: typeAlias.getCluster(symExpr)) {
                if (memoryAccessMap.containsKey(alias)) {
                    isRedundant = false;
                    break;
                }
            }
            if (isRedundant) {
                Logging.info("AccessPoints", String.format("Remove redundant argument ap for [%s]", symExpr));
            }
            return isRedundant;
        });
    }
}

