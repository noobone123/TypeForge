package blueprint.base.dataflow;

import ghidra.program.model.data.DataType;

import java.util.TreeMap;
import java.util.UUID;


public class TypeBuilder {

    /**
     * fieldMap stores the possible data types and corresponding accessed time of each fields in the structure.
     * For Example:
     * <p>
     * fieldMap {
     *     Offset_1 -> FieldEntry,
     *     Offset_2 -> FieldEntry,
     *     ...
     * }
     * </p>
     */
    public final TreeMap<Long, FieldEntry> fieldMap;
    public final UUID uuid;
    public final String shortUUID;

    public TypeBuilder() {
        fieldMap = new TreeMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
    }

    public void addPrimitive(long offset, DataType dt) {
        FieldEntry entry = fieldMap.computeIfAbsent(offset, k -> new FieldEntry());
        entry.primitiveTypeMap.merge(dt, 1, Integer::sum);
    }

    public void addTypeBuilder(long offset, TypeBuilder builder) {
        FieldEntry entry = fieldMap.computeIfAbsent(offset, k -> new FieldEntry());
        entry.typeBuilderMap.merge(builder, 1, Integer::sum);
    }

    public void addTag(long offset, String tag) {
        FieldEntry entry = fieldMap.computeIfAbsent(offset, k -> new FieldEntry());
        entry.tag.add(tag);
    }

    public boolean hasTag(long offset, String tag) {
        FieldEntry entry = fieldMap.get(offset);
        return entry != null && entry.tag.contains(tag);
    }

    /**
     * Merge dataflow facts from other TypeBuilder.
     * @param other other TypeBuilder instance.
     */
    public void merge(TypeBuilder other) {
        other.fieldMap.forEach((offset, otherEntry) -> {
            FieldEntry entry =  fieldMap.computeIfAbsent(offset, k -> new FieldEntry());

            otherEntry.primitiveTypeMap.forEach((dt, count) ->
                entry.primitiveTypeMap.merge(dt, count, Integer::sum));

            otherEntry.typeBuilderMap.forEach((builder, count) ->
                entry.typeBuilderMap.merge(builder, count, Integer::sum));

            entry.tag.addAll(otherEntry.tag);
        });
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("TypeBuilder_" + shortUUID + " {");
        // Sort the fieldMap by offset
        fieldMap.forEach((offset, entry) -> {
            sb.append("\n\tOffset_0x").append(Long.toHexString(offset)).append(" -> ");
            sb.append(entry.toString());
        });
        sb.append("\n}");
        return sb.toString();
    }
}
