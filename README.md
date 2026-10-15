Small snapshot fuzzer using libnyx as its backend

# Informations

## Harness infos

The structure of an input given to the harness is 

```c
struct Input {
    int32_t size,
    uint8_t workerId,
    uint8_t buffer[]
}
```

However the mutator only sees the ```buffer``` part and the workerId is added under the hood.

## Mutator 

You can add a custom mutator by extending the ```Mutator_t``` class.
Exemples are available in `mutator.cpp` but the idea is as following

```c
class MyMutator_t : public Mutator_t { ... };
REGISTER_MUTATOR(MyMutator_t, "mine", "my custom strategy");
```