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
    private final Map<SymbolExpr, Set<AP>> memoryAccessMap;
    private final Map<SymbolExpr, Set<AP>> argAccessMap;

    public AccessPoints() {
        memoryAccessMap = new HashMap<>();
        argAccessMap = new HashMap<>();
    }

    public void addMemAccessPoint(SymbolExpr symExpr, PcodeOp op, TypeDescriptor type, AccessType accessType) {
        memoryAccessMap.putIfAbsent(symExpr, new HashSet<>());
        memoryAccessMap.get(symExpr).add(new AP(op, type, accessType));
        Logging.info(String.format("[AP] Add %s access point for [%s] with type [%s]", accessType, symExpr, type.getName()));
    }

    public void addArgAccessPoint(SymbolExpr symExpr, PcodeOp op, AccessType accessType) {
        argAccessMap.putIfAbsent(symExpr, new HashSet<>());
        argAccessMap.get(symExpr).add(new AP(op, null, accessType));
        Logging.info(String.format("[AP] Add %s access point for [%s] with type [null]", accessType, symExpr));
    }

    public Map<SymbolExpr, Set<AP>> getMemoryAccessMap() {
        return memoryAccessMap;
    }

    public Set<AP> getMemoryAccessPoints(SymbolExpr symExpr) {
        return memoryAccessMap.get(symExpr);
    }

    public Map<SymbolExpr, Set<AP>> getArgAccessMap() {
        return argAccessMap;
    }

    public Set<AP> getArgAccessPoints(SymbolExpr symExpr) {
        return argAccessMap.get(symExpr);
    }

    /**
     * For all Expressions in AccessPoints, some of them is not considered as Composite DataType, so we need to remove
     * these redundant expressions by checking if their alias Expr has memory access.
     * @param typeAlias the alias of all expressions
     */
    public void removeRedundantAPs(UnionFind<SymbolExpr> typeAlias) {
        argAccessMap.keySet().removeIf(symExpr -> {
            boolean isRedundant = true;
            for (var alias: typeAlias.getCluster(symExpr)) {
                if (memoryAccessMap.containsKey(alias)) {
                    isRedundant = false;
                    break;
                }
            }
            if (isRedundant) {
                Logging.info(String.format("[AP] Remove redundant argument access point for [%s]", symExpr));
            }
            return isRedundant;
        });
    }
}

