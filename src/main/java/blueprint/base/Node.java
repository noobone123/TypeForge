package blueprint.base;

import java.util.HashSet;
import java.util.Set;

public class Node<T> {

    private final T value;
    private int id;

    /**
     * The pred of this node
     */
    public final Set<T> pred = new HashSet<>();

    /**
     * The succ of this node
     */
    public final Set<T> succ = new HashSet<>();

    /**
     * Create a node from the given parameter
     */
    public Node(T value, int id) {
        this.value = value;
        this.id = id;
    }

    @Override
    public int hashCode() {
        return value != null ? value.hashCode() : 0;
    }
}