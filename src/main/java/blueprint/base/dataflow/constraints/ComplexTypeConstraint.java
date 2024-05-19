package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoint;
import blueprint.base.dataflow.SymbolExpr;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.PcodeOp;

import java.util.*;
import java.util.stream.Collectors;

public class ComplexTypeConstraint implements TypeDescriptor {
    /**
     * For a complexType, the fieldMap is a map from the offset of the field to the field's type.
     * Be careful that there maybe multiple dataTypes at the same offset in the fieldMap because of the union or array.
     * <code>
     * ComplexTypeConstraints {
     *     offset_1 : {type_1 : access_time, type_2 : access_time, ...},
     *     offset_2 : {type_1 : access_time, type_2 : access_time, ...},
     *     ...
     * }
     * </code>
     */
    public final TreeMap<Long, HashMap<TypeDescriptor, Integer>> fieldMap;
    public final TreeMap<Long, HashSet<String>> tags;

    public final HashSet<AccessPoint> accessPoints;
    public long size = 0;

    public final UUID uuid;
    public final String shortUUID;

    public ComplexTypeConstraint() {
        accessPoints = new HashSet<>();
        fieldMap = new TreeMap<>();
        tags = new TreeMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
    }

    public void addField(long offset, TypeDescriptor type) {
        fieldMap.putIfAbsent(offset, new HashMap<>());
        fieldMap.get(offset).put(type, fieldMap.get(offset).getOrDefault(type, 0) + 1);
    }

    public void addAccessPoint(AccessPoint ap) {
        accessPoints.add(ap);
    }

    public HashSet<AccessPoint> getAccessPoints() {
        return accessPoints;
    }

    public void mergeAccessPoints(ComplexTypeConstraint other) {
        accessPoints.addAll(other.accessPoints);
    }


//    public void buildConstraint() {
//        Map<PcodeOp, Set<AccessPoint>> groupedAP = accessPoints.stream()
//                .collect(Collectors.groupingBy(
//                        ap -> ap.pcodeOp,
//                        Collectors.toSet()
//                ));
//
//        groupedAP.replaceAll((pcodeOp, apSet) -> new HashSet<>(apSet.stream()
//                .collect(Collectors.toMap(
//                        ap -> ap.symExpr,
//                        ap -> ap,
//                        (ap1, ap2) -> ap1
//                ))
//                .values())
//        );
//
//        groupedAP.forEach((pcodeOp, apSet) -> {
//            // TODO: if PCodeOp is the same, but the SymbolExpr is different, maybe means loop?
//            if (apSet.size() > 1) {
//                Logging.warn("Multiple AccessPoints in the same PcodeOp");
//                Logging.warn(apSet.toString());
//            }
//
//            apSet.forEach(ap -> {
//                SymbolExpr symExpr = ap.symExpr;
//                // TODO: consider the nested SymbolExpr
//                if (symExpr.isNested()) {
//                    Logging.warn("Nested SymbolExpr in AccessPoint");
//                } else {
//                    addField(symExpr.getOffset(), ap.type);
//                }
//            });
//        });
//    }


    public void merge(ComplexTypeConstraint other) {
        // Merging fields from other ComplexType
        other.fieldMap.forEach((offset, typeMap) -> {
            if (!this.fieldMap.containsKey(offset)) {
                this.fieldMap.put(offset, new HashMap<>(typeMap));
            } else {
                typeMap.forEach((type, count) ->
                        this.fieldMap.get(offset).merge(type, count, Integer::sum));
            }
        });

        // Merging tags
        other.tags.forEach((offset, tagSet) -> {
            this.tags.putIfAbsent(offset, new HashSet<>());
            this.tags.get(offset).addAll(tagSet);
        });
    }

    public void setSize(long size) {
        if (size != this.size) {
            this.size = size;
            Logging.info(String.format("ComplexType_%s setting new size: %d", shortUUID, size));
        }
    }


    @Override
    public String getName() {
        return shortUUID;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ComplexType_" + shortUUID + " {\n");
        fieldMap.forEach((offset, typeMap) -> {
            sb.append("0x").append(Long.toHexString(offset)).append(" : {");
            typeMap.forEach((type, count) -> sb.append(type.getName()).append(" : ").append(count).append(", "));
            sb.append("}, \n");
        });
        sb.append("}");
        return sb.toString();
    }

    @Override
    public int hashCode() {
        return uuid.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ComplexTypeConstraint) {
            return this.uuid.equals(((ComplexTypeConstraint) obj).uuid);
        }
        return false;
    }
}
