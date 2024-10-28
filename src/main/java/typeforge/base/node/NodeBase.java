package typeforge.base.node;

import java.util.HashSet;
import java.util.Set;

public abstract class NodeBase<T> {
    public final T value;
    public int id;

    /** The pred of this node */
    public final Set<NodeBase<T>> pred = new HashSet<>();

    /** The succ of this node */
    public final Set<NodeBase<T>> succ = new HashSet<>();

    /** Create a node from the given parameter */
    public NodeBase(T value, int id) {
        this.value = value;
        this.id = id;
    }

    @Override
    public int hashCode() {
        return value != null ? value.hashCode() : 0;
    }
}