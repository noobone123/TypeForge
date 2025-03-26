package typeforge.base.dataflow;

import typeforge.base.dataflow.expression.NMAE;
import typeforge.utils.DataTypeHelper;
import typeforge.utils.Logging;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
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
        public final Function func;
        public DataType dataType;

        /** accessType: including:
         * 0: load
         * 1: store
         * 2: argument
         * 3. RETURN_VALUE
         */
        public AccessType accessType;

        public AP(PcodeOp pcodeOp, DataType type, AccessType accessType, Function func) {
            this.pcodeOp = pcodeOp;
            if (accessType != AccessType.ARGUMENT) {
                assert type != null;
                this.dataType = type;
            }
            else {
                this.dataType = null;
            }
            this.accessType = accessType;
            this.func = func;
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

    public static class APSet {
        public final Set<AP> apSet;
        public boolean isSameSizeType = true;
        public int maxDTSize = -1;
        public int minDTSize = -1;
        public int DTSize = -1;
        public DataType mostAccessedDT = null;
        public Set<DataType> allDTs = new HashSet<>();

        public APSet() {
            this.apSet = new HashSet<>();
        }

        public APSet(APSet other) {
            this.apSet = new HashSet<>(other.apSet);
            this.isSameSizeType = other.isSameSizeType;
            this.maxDTSize = other.maxDTSize;
            this.minDTSize = other.minDTSize;
            this.DTSize = other.DTSize;
            this.mostAccessedDT = other.mostAccessedDT;
            this.allDTs = new HashSet<>(other.allDTs);
        }

        public void addAll(Set<AP> apSet) {
            this.apSet.addAll(apSet);
        }

        public void update(APSet other) {
            this.apSet.addAll(other.apSet);
            postHandle();
        }

        public boolean addAP(AP ap) {
            return apSet.add(ap);
        }

        public Set<AP> getApSet() {
            return apSet;
        }

        public int getAPCount() {
            return apSet.size();
        }

        public Map<DataType, Integer> getTypeFreq() {
            Map<DataType, Integer> typeFreq = new HashMap<>();
            for (var ap: apSet) {
                typeFreq.putIfAbsent(ap.dataType, 0);
                typeFreq.put(ap.dataType, typeFreq.get(ap.dataType) + 1);
            }
            return typeFreq;
        }

        public void postHandle() {
            /* Avoid using undefined data type */
            for (var ap: apSet) {
                if (ap.dataType instanceof Undefined || ap.dataType instanceof DefaultDataType) {
                    ap.dataType = DataTypeHelper.getDataTypeInSize(ap.dataType.getLength());
                } else if (ap.dataType instanceof Pointer && ((Pointer) ap.dataType).getDataType() instanceof Undefined) {
                    var dt = DataTypeHelper.getDataTypeInSize(ap.dataType.getLength());
                    ap.dataType = DataTypeHelper.getPointerDT(dt, 1);
                }
            }

            isSameSizeType = AccessPoints.ifAPSetHoldsSameSizeType(apSet);
            if (isSameSizeType) {
                DTSize = AccessPoints.getDataTypeSize(apSet);
                maxDTSize = DTSize;
                minDTSize = DTSize;
            } else {
                maxDTSize = AccessPoints.getMaxSizeInAPSet(apSet);
                minDTSize = AccessPoints.getMinSizeInAPSet(apSet);
            }

            mostAccessedDT = AccessPoints.getMostAccessedDT(apSet);
            allDTs = AccessPoints.getDataTypes(apSet);
        }
    }


    /**
     * Each SymbolExpr in function may be accessed by multiple PcodeOps with different types.
     * So we need to record all the access points of each SymbolExpr.
     */

    /** Expressions in memAccessMap: (param + 1) means there is a load/store into (param + 1), loaded value can be represented as *(param + 1) */
    private final Map<NMAE, Set<AP>> fieldExprToAccessMap;

    public AccessPoints() {
        fieldExprToAccessMap = new HashMap<>();
    }

    public void addFieldAccessPoint(NMAE symExpr, PcodeOp op, DataType type, AccessType accessType, Function func) {
        fieldExprToAccessMap.putIfAbsent(symExpr, new HashSet<>());
        fieldExprToAccessMap.get(symExpr).add(new AP(op, type, accessType, func));
        Logging.trace("AccessPoints", String.format("Add Field Access %s for [%s] with type [%s]", accessType, symExpr, type.getName()));
    }

    public Set<AP> getFieldAccessPoints(NMAE symExpr) {
        return fieldExprToAccessMap.get(symExpr);
    }

    public static boolean ifAPSetHoldsSameSizeType(Set<AccessPoints.AP> apSet) {
        if (apSet.isEmpty()) {
            return false;
        }
        var firstAP = apSet.iterator().next();
        var firstDT = firstAP.dataType;
        for (var ap : apSet) {
            if (!(firstDT.getLength() == ap.dataType.getLength())) {
                return false;
            }
        }
        return true;
    }

    public static int getMaxSizeInAPSet(Set<AccessPoints.AP> apSet) {
        if (apSet.isEmpty()) {
            return 0;
        }
        var maxSize = 0;
        for (var ap : apSet) {
            if (ap.dataType.getLength() > maxSize) {
                maxSize = ap.dataType.getLength();
            }
        }
        return maxSize;
    }

    public static int getMinSizeInAPSet(Set<AccessPoints.AP> apSet) {
        if (apSet.isEmpty()) {
            return 0;
        }
        var minSize = Integer.MAX_VALUE;
        for (var ap : apSet) {
            if (ap.dataType.getLength() < minSize) {
                minSize = ap.dataType.getLength();
            }
        }
        return minSize;
    }

    public static DataType getMostAccessedDT(Set<AccessPoints.AP> apSet) {
        Map<DataType, Integer> apCount = new HashMap<>();
        apSet.forEach(ap -> {
            apCount.putIfAbsent(ap.dataType, 0);
            apCount.put(ap.dataType, apCount.get(ap.dataType) + 1);
        });

        /* Find DataType with Max access count */
        var maxCount = 0;
        DataType maxDT = null;
        for (var entry: apCount.entrySet()) {
            if (entry.getValue() > maxCount) {
                maxCount = entry.getValue();
                maxDT = entry.getKey();
            }
        }
        return maxDT;
    }

    public static Set<DataType> getDataTypes(Set<AccessPoints.AP> apSet) {
        Set<DataType> dataTypes = new HashSet<>();
        for (var ap: apSet) {
            dataTypes.add(ap.dataType);
        }
        return dataTypes;
    }

    public static int getDataTypeSize(Set<AccessPoints.AP> apSet) {
        if (apSet.isEmpty()) {
            return 0;
        }
        return apSet.iterator().next().dataType.getLength();
    }
}

