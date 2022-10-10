use lnk_parser::LNKParser;
use winparsingtools::traits::Path;
use std::env;

#[derive(Debug)]
struct Lnk {
    //Lnk 文件路径
    path: String,
    //Lnk 文件的标识 可能为空
    name_string: String,
    //Lnk 指向的文件的相对路径，相对于工作目录，也可能为空（混淆）
    relative_path: String,
    //Lnk 的工作目录（运行的目录）
    working_dir: String,
    //Lnk 实际运行的文件路径。
    target_file: String,
    //Lnk 打开时指定的命令行参数
    command_line_arguments: String,
    //Lnk 文件的图标路径
    icon_location: String,
}
fn main() {
    let args: Vec<String> = env::args().collect();
    let lnk_path = &args[1];
    let res = general_lnk(lnk_path);
    // println!("{:?}", res)
    check_malicious_lnk(res)
}

//从生成 LnK 结构体
fn general_lnk(lnk_path: &String) -> Lnk {
    let lnk = LNKParser::from_path(lnk_path).unwrap();
    Lnk {
        path: lnk_path.to_string(),
        name_string: match lnk.name_string {
            Some(name_string) => name_string.to_string(),
            None => String::from("None"),
        },
        relative_path: match lnk.relative_path {
            Some(relative_path) => relative_path.to_string(),
            None => String::from("None"),
        },
        working_dir: match lnk.working_dir {
            Some(working_dir) => working_dir.to_string(),
            None => String::from("None"),
        },
        target_file: match lnk.link_target_id_list {
            Some(link_target_id_list) => match link_target_id_list.id_list.path() {
                Some(path) => path,
                None => String::from("None"),
            },
            None => String::from("None"),
        },
        command_line_arguments: match lnk.command_line_arguments {
            Some(command_line_arguments) => command_line_arguments.to_string(),
            None => String::from("None"),
        },
        icon_location: match lnk.icon_location {
            Some(icon_location) => icon_location.to_string(),
            None => String::from("None"),
        },
    }
}

fn check_malicious_lnk(lnk: Lnk) {
    let filename = lnk.path;
    let target_file = lnk.target_file;
    let command_line = lnk.command_line_arguments;

    if check_target_file(&target_file) || check_command_line(&command_line) {
        println!(
            "{} is malicious. Details:\n {} {}",
            filename, target_file, command_line
        );
    }
}

fn check_target_file(target_file: &String) -> bool {
    let black_exe_list: Vec<&str> = vec![
        "\\cmd.exe",
        "\\powershell.exe",
        "\\wscript.exe",
        "\\cscript.exe",
        "\\rundll32.exe",
        "\\msiexec.exe",
        "\\mshta.exe",
        "\\regsvr32.exe",
        "\\msdt.exe",
        "\\wmic.exe"
    ];
    for black in black_exe_list {
        if target_file.to_lowercase().ends_with(black) {
            return true;
        }
    }
    return false;
}
fn check_command_line(command_line: &String) -> bool {
    let black_exe_list: Vec<&str> = vec![
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "msiexec.exe",
        "mshta.exe",
        "regsvr32.exe",
        "msdt.exe",
        "wmic.exe"
    ];
    let black_cmd_list:Vec<&str> = vec![
        "&&",
        "||",
        "http://",
        "https://",
        "ftp://"
    ];
    for black in black_exe_list {
        if command_line.to_lowercase().ends_with(black) {
            return true;
        }
    }
    for black in black_cmd_list {
        if command_line.to_lowercase().ends_with(black) {
            return true;
        }
    }
    return false;
}
