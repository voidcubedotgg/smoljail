use clap::{Command, command, value_parser, arg};

fn cli() -> clap::Command {
    clap::Command::new("smoljail")
        .version("0.1.0")
        .author("Petr Václavek (Rispy) <petr@vaclavek.cloud>")
        .about("The smoljail provide extra layer of security to smolvm on Linux machines.")
        .arg(arg!(--id <ID> "Unique identifier for the jail").required(true))
        .arg(
            arg!(--smolvm_bin <FILE> "Path to the smolvm binary")
                .value_parser(clap::value_parser!(std::path::PathBuf))
                .required(true),
        )
        .arg(arg!(-u --user <UID> "User to run the jail under").required(true))
        .arg(arg!(-g --group <GID> "Group to run the jail under").required(true))
        .arg(
            arg!(-c --chroot_base_dir <PATH> "Directory base to chroot into")
                .value_parser(clap::value_parser!(std::path::PathBuf))
                .default_value(" /var/lib/smolvm")
                .required(false),
        )
}

fn main() {
    let matches = cli().get_matches();

    let id = matches.get_one::<String>("id").unwrap();
    let smolvm_bin = matches.get_one::<std::path::PathBuf>("smolvm_bin").unwrap();
    let user = matches.get_one::<String>("user").unwrap();
    let group = matches.get_one::<String>("group").unwrap();
    let chroot_base_dir = matches.get_one::<std::path::PathBuf>("chroot_base_dir").unwrap();

    println!("Starting smoljail with the following configuration:");
    println!("ID: {}", id);
    println!("SmolVM Binary: {}", smolvm_bin.display());
    println!("User: {}", user);
    println!("Group: {}", group);
    println!("Chroot Base Directory: {}", chroot_base_dir.display());
}
