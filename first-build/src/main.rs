mod helper;

fn main() {
    helper::public_available();
    println!("Sum of 1 and 2 is {}", helper::public_sum(1, 2));

    println!("Hello, world!");
}
