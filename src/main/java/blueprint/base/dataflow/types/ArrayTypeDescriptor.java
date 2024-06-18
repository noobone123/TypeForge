package blueprint.base.dataflow.types;

public class ArrayTypeDescriptor implements TypeDescriptor {
    private String name = null;
    private TypeDescriptor elementType = null;
    private int length = -1;

    public ArrayTypeDescriptor(TypeDescriptor elementType, int length) {
        this.elementType = elementType;
        this.length = length;
    }

    public ArrayTypeDescriptor(TypeDescriptor elementType, int length, String name) {
        this.elementType = elementType;
        this.length = length;
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return String.format("ArrayType{%s, %d}", elementType.getName(), length);
    }

    @Override
    public int hashCode() {
        return this.elementType.hashCode() + this.length;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ArrayTypeDescriptor other) {
            return this.elementType.equals(other.elementType) && this.length == other.length;
        }
        return false;
    }
}
