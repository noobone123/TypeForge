package blueprint.solver;

import ghidra.program.model.data.DataType;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.HashMap;
import java.util.Set;

public class TypeBuilder {

    /**
     * fieldMap stores the possible data types of the fields in the structure.
     * For Example:
     * <p>
     * fieldMap {
     *     Offset_1 -> Set<DataType>
     *     Offset_2 -> Set<uint, int, unknown32>
     *     Offset_3 -> Set<uchar, char, unknown32>
     *     Offset_4 -> Set<void*, ObjectA *, ObjectB *, ObjectC *>
     *     ...
     *     Offset_n -> Set<char[32], short[16], int[8], long[4]>
     * }
     * </p>
     */
    private final HashMap<Long, Set<DataType>> fieldMap;

    public TypeBuilder() {
        fieldMap = new HashMap<>();
    }

    /**
     * Add a data type to the context
     * @param offset the offset of the field
     * @param dt the field's data type
     * @return true if the data type is added successfully
     */
    public boolean addDataType(long offset, DataType dt) {
        if (!fieldMap.containsKey(offset)) {
            fieldMap.put(offset, new HashSet<>());
        }

        return fieldMap.get(offset).add(dt);
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("TypeBuilder{");
        // sort the fieldMap by offset
        var sortedFieldMap = new LinkedList<>(fieldMap.keySet());
        sortedFieldMap.sort(Long::compareTo);
        for (var offset : sortedFieldMap) {
            sb.append("\n\tOffset_").append(Long.toHexString(offset)).append(" -> ");
            sb.append(fieldMap.get(offset));
        }
        sb.append("\n}");
        return sb.toString();
    }
}
