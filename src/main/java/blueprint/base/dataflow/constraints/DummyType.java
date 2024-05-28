package blueprint.base.dataflow.constraints;

public class DummyType implements TypeDescriptor {

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
        return "dummy";
    }
}
