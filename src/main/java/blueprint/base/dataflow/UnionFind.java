package blueprint.base.dataflow;

import blueprint.utils.Logging;
import edu.uci.ics.jung.visualization.transform.shape.HyperbolicShapeTransformer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class UnionFind<T> {
    private final Map<T, T> parent;
    private final Map<T, Integer> rank;

    public UnionFind() {
        this.parent = new HashMap<>();
        this.rank = new HashMap<>();
    }

    // Add a new element to the union-find structure
    public void add(T element) {
        if (!parent.containsKey(element)) {
            parent.put(element, element);
            rank.put(element, 0);
        }
    }

    // Find the root of the element with path compression
    public T find(T element) {
        if (!parent.containsKey(element)) {
            throw new IllegalArgumentException("Element not found in UnionFind structure");
        }

        if (!parent.get(element).equals(element)) {
            parent.put(element, find(parent.get(element))); // Path compression
        }
        return parent.get(element);
    }

    // Union two elements by rank
    public void union(T element1, T element2) {
        T root1 = find(element1);
        T root2 = find(element2);

        if (!root1.equals(root2)) {
            int rank1 = rank.get(root1);
            int rank2 = rank.get(root2);

            if (rank1 > rank2) {
                parent.put(root2, root1);
            } else if (rank1 < rank2) {
                parent.put(root1, root2);
            } else {
                parent.put(root2, root1);
                rank.put(root1, rank1 + 1);
            }
        }
    }

    // Check if two elements are in the same set
    public boolean connected(T element1, T element2) {
        return find(element1).equals(find(element2));
    }

    public boolean contains(T element) {
        return parent.containsKey(element);
    }

    public Set<T> getCluster(T element) {
        Set<T> cluster = new HashSet<>();
        T root = find(element);
        for (T key : parent.keySet()) {
            if (find(key).equals(root)) {
                cluster.add(key);
            }
        }
        return cluster;
    }

    public Set<Set<T>> getClusters() {
        Map<T, Set<T>> clusters = new HashMap<>();
        for (T element : parent.keySet()) {
            T root = find(element);
            clusters.computeIfAbsent(root, k -> new HashSet<>()).add(element);
        }
        return new HashSet<>(clusters.values());
    }

    public void initializeWithCluster(Set<T> cluster) {
        T first = null;
        for (T element : cluster) {
            add(element);
            if (first == null) {
                first = element;
            } else {
                union(first, element);
            }
        }
    }
}

