package typeclay.base.dataflow.types;

public class DummyType implements TypeDescriptor {

    private final String name;

    public DummyType(String name) {
        this.name = name;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof DummyType;
    }

    @Override
    public String getName() {
        return "(dummy)" + name;
    }
}
