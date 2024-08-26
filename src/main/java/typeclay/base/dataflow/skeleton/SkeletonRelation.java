package typeclay.base.dataflow.skeleton;


public class SkeletonRelation {
    public enum RelationType {
        REFERENCE,
        NEST
    }

    public RelationType type;
    public Skeleton from;
    public Skeleton to;
    public Long offset;

    public SkeletonRelation(RelationType type, Skeleton from, Skeleton to, Long offset) {
        this.type = type;
        this.from = from;
        this.to = to;
        this.offset = offset;
    }
}
