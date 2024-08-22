package blueprint.base.dataflow;

import java.util.Objects;

public class Range {
    private final long start;
    private final long end;

    public Range(Long start, Long end) {
        this.start = start;
        this.end = end;
    }

    public long getStart() {
        return start;
    }

    public long getEnd() {
        return end;
    }

    @Override
    public int hashCode() {
        return Objects.hash(start, end);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Range range = (Range) o;
        return Objects.equals(start, range.start) &&
                Objects.equals(end, range.end);
    }
}
