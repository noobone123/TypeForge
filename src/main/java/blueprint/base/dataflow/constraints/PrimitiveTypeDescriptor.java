package blueprint.base.dataflow.constraints;

import ghidra.program.model.data.DataType;

public class PrimitiveTypeDescriptor implements TypeDescriptor {
    private final DataType type;
    private final String typeName;

    public PrimitiveTypeDescriptor(DataType type) {
        this.type = type;
        this.typeName = type.getName();
    }


    @Override
    public String getName() {
        return typeName;
    }

    @Override
    public String toString() {
        return "PrimitiveType{" +
                "typeName='" + typeName + '\'' +
                '}';
    }

    @Override
    public int hashCode() {
        return this.type.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof PrimitiveTypeDescriptor) {
            return this.type.equals(((PrimitiveTypeDescriptor) obj).type);
        }
        return false;
    }
}
