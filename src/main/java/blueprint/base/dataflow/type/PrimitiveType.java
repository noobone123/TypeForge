package blueprint.base.dataflow.type;

import ghidra.program.model.data.DataType;

public class PrimitiveType implements GeneralType {
    private final DataType type;
    private final String typeName;

    public PrimitiveType(DataType type) {
        this.type = type;
        this.typeName = type.getName();
    }

    @Override
    public String getTypeName() {
        return typeName;
    }

    @Override
    public String toString() {
        return "PrimitiveType{" +
                "typeName='" + typeName + '\'' +
                '}';
    }
}
