package typeforge.base.dataflow.types;

import typeforge.base.dataflow.skeleton.TypeConstraint;

import java.util.*;

/**
 * Layout class is used to describe the layout of a composite data type.
 * Actually, layout is just a List of intervals, where each interval is a pair of offset and size.
 */
public class Layout {

    public static class Interval {
        public long offset;
        public Set<Integer> sizes;

        public Interval(long offset, Set<Integer> sizes) {
            this.offset = offset;
            this.sizes = sizes;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Interval interval = (Interval) o;
            return offset == interval.offset && sizes.equals(interval.sizes);
        }

        @Override
        public int hashCode() {
            return Objects.hash(offset, sizes);
        }
    }

    public List<Interval> intervals;

    public Layout(TypeConstraint constraint) {
        intervals = new ArrayList<>();
        constraint.fieldAccess.forEach((offset, aps) -> {
            Set<Integer> sizes = new HashSet<>();
            for (var ap: aps.getApSet()) {
                sizes.add(ap.dataType.getLength());
            }
            intervals.add(new Interval(offset, sizes));
        });
    }

    public Layout(List<Interval> intervals) {
        this.intervals = intervals;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                intervals.stream().map(interval -> interval.offset).toArray()
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Layout layout = (Layout) o;

        if (this.intervals.size() != layout.intervals.size()) return false;
        for (int i = 0; i < this.intervals.size(); i++) {
            if (this.intervals.get(i).offset != layout.intervals.get(i).offset) {
                return false;
            }
        }
        return true;
    }
}
