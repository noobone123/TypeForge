package typeforge.base.dataflow;

import typeforge.utils.Logging;

import java.util.HashSet;
import java.util.Iterator;

/**
 * KSet is a set with a maximum size.
 * If the set is full, then the add operation will return false.
 * @param <E> the element type
 */
public class KSet<E> implements Iterable<E> {
    private final HashSet<E> set;
    private final int maxSize;

    public KSet(int maxSize) {
        this.maxSize = maxSize;
        this.set = new HashSet<>();
    }

    public boolean add(E element) {
        if (set.size() >= maxSize) {
            Logging.warn("KSet", "Set is full, cannot add element: " + element);
            return false;
        }
        return set.add(element);
    }

    public boolean isEmpty() {
        return set.isEmpty();
    }

    public boolean contains(E element) {
        return set.contains(element);
    }

    public void merge(KSet<E> other) {
        for (E element : other.set) {
            if (this.set.size() >= this.maxSize) {
                break;
            }
            this.add(element);
        }
    }

    @Override
    public String toString() {
        return set.toString();
    }

    @Override
    public Iterator<E> iterator() {
        return set.iterator();
    }

    public void clear() {
        set.clear();
    }

}