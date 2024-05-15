package blueprint.base.dataflow.constraints;

import blueprint.base.dataflow.AccessPoint;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.PcodeOp;
import groovy.util.logging.Log;

import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeMap;
import java.util.UUID;

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
        HashSet<PcodeOp> exists = new HashSet<>();
        accessPoints.forEach(ap -> exists.add(ap.pcodeOp));

        for (var ap: other.accessPoints) {
            if (!exists.contains(ap.pcodeOp)) {
                accessPoints.add(ap);
                exists.add(ap.pcodeOp);
            }
        }
    }


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


    public void buildFieldConstraint() {
        accessPoints.forEach(ap -> {
            addField(ap.symExpr.offset, ap.type);
        });
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
