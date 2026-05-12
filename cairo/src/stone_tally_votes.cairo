use crate::public_output::{TallyPublicFields, TallyPublicOutput};
use crate::tally_votes::{TallyWitness, main as tally_votes_main};

#[executable]
pub fn tally_votes_stone_main(input: Array<felt252>) -> Array<felt252> {
    let mut serialized = input.span();
    let fields: TallyPublicFields = Serde::<TallyPublicFields>::deserialize(ref serialized)
        .expect('STONE_TALLY_FIELDS');
    let witness: TallyWitness = Serde::<TallyWitness>::deserialize(ref serialized)
        .expect('STONE_TALLY_WITNESS');
    assert(serialized.len() == 0, 'STONE_TALLY_ARGS');

    let output: TallyPublicOutput = tally_votes_main(fields, witness);
    let mut serialized_output = array![];
    output.serialize(ref serialized_output);
    serialized_output
}
