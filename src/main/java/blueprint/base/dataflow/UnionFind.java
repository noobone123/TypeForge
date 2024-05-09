package blueprint.base.dataflow;

import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

public class UnionFind<T> {
    private final Map<T, T> parent = new HashMap<>();
    private final Map<T, Integer> rank = new HashMap<>();
    private final Map<T, Set<T>> components = new HashMap<>();

    private void ensureSet(T element) {
        if (!parent.containsKey(element)) {
            parent.put(element, element);
            rank.put(element, 0);

            HashSet<T> newSet = new HashSet<>();
            newSet.add(element);
            components.put(element, newSet);
        }
    }

    public T find(T s) {
        ensureSet(s);
        if (parent.get(s) != s) {
            parent.put(s, find(parent.get(s)));
        }
        return parent.get(s);
    }

    public void union(T x, T y) {
        ensureSet(x);
        ensureSet(y);

        T xRoot = find(x);
        T yRoot = find(y);

        if (xRoot == yRoot) {
            return;
        }
        if (rank.get(xRoot) < rank.get(yRoot)) {
            parent.put(xRoot, yRoot);
            // add all elements in a larger root
            components.get(yRoot).addAll(components.get(xRoot));
            components.remove(xRoot);
        } else if (rank.get(xRoot) > rank.get(yRoot)) {
            parent.put(yRoot, xRoot);
            components.get(xRoot).addAll(components.get(yRoot));
            components.remove(yRoot);
        } else {
            parent.put(yRoot, xRoot);
            components.get(xRoot).addAll(components.get(yRoot));
            components.remove(yRoot);
            rank.put(xRoot, rank.get(xRoot) + 1);
        }
    }

    public Map<T, Set<T>> getComponents() {
        return components;
    }
}
