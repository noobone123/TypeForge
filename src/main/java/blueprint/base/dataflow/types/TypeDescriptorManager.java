package blueprint.base.dataflow.types;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;

public class TypeDescriptorManager {

    public static TypeDescriptor createPrimitiveTypeDescriptor(DataType type) {
        return new PrimitiveTypeDescriptor(type);
    }

    public static TypeDescriptor createCompositeTypeDescriptor(Composite type) {
        return new CompositeTypeDescriptor(type);
    }

    public static TypeDescriptor createArrayTypeDescriptor(Array type) {
        var arrayName = type.getName();
        var arrayLength = type.getNumElements();
        var elementType = type.getDataType();
        if (elementType instanceof Composite composite) {
            return new ArrayTypeDescriptor(createCompositeTypeDescriptor(composite), arrayLength, arrayName);
        } else if (elementType instanceof Array array) {
            return new ArrayTypeDescriptor(createArrayTypeDescriptor(array), arrayLength, arrayName);
        } else {
            return new ArrayTypeDescriptor(createPrimitiveTypeDescriptor(elementType), arrayLength, arrayName);
        }
    }
}
