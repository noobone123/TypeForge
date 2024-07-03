package blueprint.base.dataflow.constraints;


public class TCRelation {
    public enum RelationType {
        REFERENCE,
        NEST
    }

    public RelationType type;
    public TypeConstraint from;
    public TypeConstraint to;
    public Long offset;

    public TCRelation(RelationType type, TypeConstraint from, TypeConstraint to, Long offset) {
        this.type = type;
        this.from = from;
        this.to = to;
        this.offset = offset;
    }
}
