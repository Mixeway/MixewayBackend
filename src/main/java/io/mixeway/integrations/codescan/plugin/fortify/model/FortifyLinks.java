package io.mixeway.integrations.codescan.plugin.fortify.model;

public class FortifyLinks {
    FortifyLink next;
    FortifyLink last;
    FortifyLink first;

    public FortifyLink getNext() {
        return next;
    }

    public void setNext(FortifyLink next) {
        this.next = next;
    }

    public FortifyLink getLast() {
        return last;
    }

    public void setLast(FortifyLink last) {
        this.last = last;
    }

    public FortifyLink getFirst() {
        return first;
    }

    public void setFirst(FortifyLink first) {
        this.first = first;
    }
}
