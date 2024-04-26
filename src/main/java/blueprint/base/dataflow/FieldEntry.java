package blueprint.base.dataflow;

import ghidra.program.model.data.DataType;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * FieldEntry indicates possible field data types and accessed times of a field in a structure.
 */
public class FieldEntry {
    /**
     * primitiveTypeMap stores the accessed time of each primitive data type.
     * For Example:
     * <p>
     * primitiveTypeMap {
     *     DataType_1 -> count_1,
     *     DataType_2 -> count_2,
     *     ...
     * }
     * </p>
     */
    public Map<DataType, Integer> primitiveTypeMap;

    /**
     * typeBuilderMap stores the accessed time of each complex data type (Structure, Union, etc ...).
     */
    public Map<TypeBuilder, Integer> typeBuilderMap;

    /**
     * tag is used to store the tag of the field. All TAG includes:
     *
     */
    public Set<String> tag;

    public FieldEntry() {
        primitiveTypeMap = new HashMap<>();
        typeBuilderMap = new HashMap<>();
        tag = new HashSet<>();
    }

    public String toString() {
        var sb = new StringBuilder();
        sb.append("FieldEntry{ ");
        sb.append("primType: <");
        primitiveTypeMap.forEach((dt, count) -> sb.append(dt.getName()).append(": ").append(count).append(", "));
        sb.append(">, ");
        sb.append("typeBuilder: <");
        typeBuilderMap.forEach((builder, count) -> sb.append(builder.shortUUID).append(": ").append(count).append(", "));
        sb.append(">, ");
        sb.append("tag: <");
        tag.forEach(t -> sb.append(t).append(", "));
        sb.append(">");
        sb.append("} ");

        return sb.toString();
    }
}