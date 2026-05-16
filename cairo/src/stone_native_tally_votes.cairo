use crate::native_tally_votes::{
    TallyNativePublicFields, TallyNativePublicOutput, TallyNativeWitness,
    main as tally_votes_native_main,
};

#[executable]
pub fn tally_votes_native_stone_main(input: Array<felt252>) -> Array<felt252> {
    let mut serialized = input.span();
    let fields: TallyNativePublicFields = Serde::<TallyNativePublicFields>::deserialize(
        ref serialized,
    )
        .expect('STONE_NATIVE_FIELDS');
    let witness: TallyNativeWitness = Serde::<TallyNativeWitness>::deserialize(ref serialized)
        .expect('STONE_NATIVE_WITNESS');
    assert(serialized.len() == 0, 'STONE_NATIVE_ARGS');

    let output: TallyNativePublicOutput = tally_votes_native_main(fields, witness);
    let mut serialized_output = array![];
    output.serialize(ref serialized_output);
    serialized_output
}
