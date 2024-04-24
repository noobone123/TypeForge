package blueprint.solver;

import blueprint.utils.Logging;

import ghidra.program.model.data.DataType;

import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.HashMap;
import java.util.HashMap;
import java.util.Set;
import java.util.Map;

public class TypeBuilder {

    /**
     * fieldMap stores the possible data types and corresponding accessed time of each fields in the structure.
     * For Example:
     * <p>
     * fieldMap {
     *     Offset_1 -> Map{DataType_1 -> accessed 1 time, ... , DataType_n -> accessed n times},
     *     Offset_2 -> Map{uint32 -> 1, int -> 10, ...},
     *     ...
     * }
     * </p>
     */
    public final HashMap<Long, Map<DataType, Integer>> fieldMap;

    public TypeBuilder() {
        fieldMap = new HashMap<>();
    }

    /**
     * Add a data type to the context
     * @param offset the offset of the field
     * @param dt the field's data type
     */
    public void addDataType(long offset, DataType dt) {
        if (!fieldMap.containsKey(offset)) {
            fieldMap.put(offset, new HashMap<>());
        }

        var typeCountMap = fieldMap.get(offset);
        if (!typeCountMap.containsKey(dt)) {
            typeCountMap.put(dt, 1);
        } else {
            typeCountMap.put(dt, typeCountMap.get(dt) + 1);
        }
    }


    /**
     * Merge dataflow facts from other TypeBuilder.
     * @param other other TypeBuilder instance.
     */
    public void merge(TypeBuilder other) {
        if (other == null) {
            return;
        }

        for (var otherEntry: other.fieldMap.entrySet()) {
            var otherKey = otherEntry.getKey();
            var otherValue = otherEntry.getValue();
            if (!fieldMap.containsKey(otherKey)) {
                fieldMap.put(otherKey, new HashMap<>(otherValue));
            } else {
                var typeCountMap = fieldMap.get(otherKey);
                for (var entry: otherValue.entrySet()) {
                    var dt = entry.getKey();
                    var count = entry.getValue();
                    if (!typeCountMap.containsKey(dt)) {
                        typeCountMap.put(dt, count);
                    } else {
                        typeCountMap.put(dt, typeCountMap.get(dt) + count);
                    }
                }
            }
        }
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("TypeBuilder {");
        // sort the fieldMap by offset
        var sortedFieldMap = new LinkedList<>(fieldMap.keySet());
        sortedFieldMap.sort(Long::compareTo);
        for (var offset : sortedFieldMap) {
            sb.append("\n\tOffset_0x").append(Long.toHexString(offset)).append(" -> ");
            sb.append("{");
            for (var entry : fieldMap.get(offset).entrySet()) {
                sb.append(entry.getKey().getName()).append(":").append(entry.getValue()).append(", ");
            }
            sb.append("}");
        }
        sb.append("\n}");
        return sb.toString();
    }
}
