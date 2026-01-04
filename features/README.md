# Using Feature Sets

Bazel configures the different modes and ways of invoking the compiler and
tools with `feature`s.  Each feature describes a set of flags to apply to
the toolchain (such as optimization level) for different actions (such
as compiling or linking).  A collection of features a gathered into a
`feature_set` and given to bazel to configure the toolchain.

CRT configures features and `feature_set`s using bazel rules.  A feature
set can reference any number of base feature sets.  All referenced
`feature`s are aggreated together in the feature set.  Features are named
by the last part of their label (the part after the colon).  In a feature
set, the last referenced feature of a given name take precedence: if
you have a feature set containing a feature named `opt` and you provide
a new feature named `opt`, the later referenced `opt` wins.

Consider a `common` feature set:
```
feature(
    name = "opt",
    flag_sets = [
        flag_set(
            flag_groups = flag_group(flags = ["-O2"])
	)
    ],
)

feature_set(
    name = "common",
    feature = [
        ":opt",
        ....
    ],
)
```

Now consider an embedded compiler configuration where the desired optimization
flag should be `-Os` instead of `-O2`.  We want to inherit all of the features
from `common`, but override the `opt` feature to use an alternate flag:
```
feature(
    name = "opt",
    flag_sets = [
        flag_set(
            flag_groups = flag_group(flags = ["-Os"])
	)
    ],
)

feature_set(
    name = "embedded",
    base = ["//features/common"]
    feature = [
        ":opt",
        ....
    ],
)
```

Feature sets and overrides are processed in order: A given `feature_set` will
process the list of `base`sn order and then apply each of the listed `feature`s. 
