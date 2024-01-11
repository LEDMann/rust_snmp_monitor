#![allow(non_snake_case, non_camel_case_types)]

mod mibobject;

use chrono::Utc;
use egui_plot::{PlotPoints, Line, Plot, Legend};
use mibobject::MibModule::{MibObject, MibValue};
use serde::Deserializer;

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions, self};
use std::io::{BufWriter, Write, BufReader, BufRead, LineWriter, Read};
use std::process::exit;
use std::str::FromStr;
use std::net::{IpAddr, SocketAddr};

use std::sync::mpsc::{Sender, Receiver};
use std::time::Duration;
use async_trait::async_trait;
use csv::Error;
use egui::{Response, Widget, WidgetText, Ui, Slider, Window, Frame};
use egui_extras::{TableBuilder, Column};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer, dock_state, SurfaceIndex, AllowedSplits};
use tokio::runtime::Builder;
use tokio::{task, time};

use serde_json::{self, Value};

use eframe::{egui, AppCreator};

use csnmp::{Snmp2cClient, ObjectValue, client, ObjectIdentifier};


struct SnmpMonitorApp {
    name: String,
    target_ip: String,
    community: String,
    mib_obj_reciever: Receiver<MibObject>,
    target_sender: Sender<(SocketAddr, String)>,
    context: MyContext,
    new_plot_window_manager: NewPlotWindowManager,
    tabs_tree: DockState<String>
}

struct MyContext {
    pub title: String,
    pub age: u32,
    pub style: Option<Style>,
    open_tabs: HashSet<String>,
    object: Option<MibObject>,
    plots: HashMap<String, PlotContext>,
    new_plot_name: String,

    show_close_buttons: bool,
    show_add_buttons: bool,
    draggable_tabs: bool,
    show_tab_name_on_hover: bool,
    allowed_splits: AllowedSplits,
    show_window_close: bool,
    show_window_collapse: bool,
}

#[derive(Clone)]
struct PlotContext {
    plottables: Vec<Plottable>,
    draggable: bool,
    axes: bool,
    scroll: bool,
    zoom: bool,
    legend: bool,
    grid: bool,
}

struct NewPlotWindowManager {
    open: bool,
    show: bool,
    value_to_add: Option<MibValue>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Plottable {
    name: String,
    oid: Vec<u16>,
    points: Vec<(i64, i64)>,
    points_max: (i64, i64),
}

impl Plottable {
    fn new(val: MibValue) -> Option<Self> {
        match val {
            MibValue::inti32(mvinti32) => Some(Plottable { 
                name: mvinti32.name, 
                oid: mvinti32.oid,
                points: vec![],
                points_max: (0, 0),
            }),
            MibValue::intu32(mvintu32) => Some(Plottable { 
                name: mvintu32.name, 
                oid: mvintu32.oid,
                points: vec![],
                points_max: (0, 0),
            }),
            MibValue::intu64(mvintu64) => Some(Plottable { 
                name: mvintu64.name, 
                oid: mvintu64.oid,
                points: vec![],
                points_max: (0, 0),
            }),
            _ => None,
        }
    }

    fn add(&mut self, point: (i64, i64)) {
        if self.points_max.0 < point.0 { self.points_max.0 = point.0 }
        if self.points_max.1 < point.1 { self.points_max.1 = point.1 }
        self.points.push(point);
    }
}

impl PlotContext {
    fn new(plottables: Vec<Plottable>) -> Self{
        PlotContext {
            plottables: plottables,
            draggable: true,
            axes: true,
            scroll: true,
            zoom: true,
            legend: true,
            grid: true,
        }
    }
}
impl TabViewer for MyContext {
    type Tab = String;

    fn title(&mut self, tab: &mut Self::Tab) -> WidgetText {
        tab.as_str().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Self::Tab) {
        match tab.as_str() {
            "ifTable" => self.object.clone().unwrap().interfaces.ifTable.egui_table_show(ui),
            "atTable" => self.object.clone().unwrap().at.atTable.egui_table_show(ui),
            "ipAddrTable" => self.object.clone().unwrap().ip.ipAddrTable.egui_table_show(ui),
            "ipRouteTable" => self.object.clone().unwrap().ip.ipRouteTable.egui_table_show(ui),
            "ipNetToMediaTable" => self.object.clone().unwrap().ip.ipNetToMediaTable.egui_table_show(ui),
            "tcpConnTable" => self.object.clone().unwrap().tcp.tcpConnTable.egui_table_show(ui),
            "udpTable" => self.object.clone().unwrap().udp.udpTable.egui_table_show(ui),
            "egpNeighTable" => self.object.clone().unwrap().egp.egpNeighTable.egui_table_show(ui),
            _ => {
                if self.plots.keys().any(|name| name.eq(tab.as_str())) {
                    self.plot(ui, tab.to_string(),  self.plots.get(tab.as_str()).unwrap().clone());
                } else {
                    ui.label(tab.as_str());
                    ui.label("we dont know what to put here");
                }
            }
        }
    }
}

impl MyContext {
    fn plot(&mut self, ui: &mut Ui, tab: String, mut plotcontext: PlotContext) {
        // println!("rendering plot called {} with {} plottables", tab, plotcontext.plottables.len());
        // println!("{:?}: {:?}", tab, plottables);
        Plot::new(tab).legend(Legend::default())
                                .allow_drag(plotcontext.draggable)
                                .show_grid(plotcontext.grid)
                                .clamp_grid(!plotcontext.grid)
                                .show_axes(plotcontext.axes)
                                .allow_zoom(plotcontext.zoom)
                                .allow_scroll(plotcontext.scroll)
                                .allow_boxed_zoom(false)
                                .auto_bounds_x()
                                .auto_bounds_y()
                                // .show_axes(false)
                                .show(ui, |plot_ui| { 
                                    plotcontext.plottables.clone()
                                            .into_iter()
                                            .enumerate()
                                            .for_each(|a| {
                                                plot_ui.line(Line::new(a.1.points.into_iter().enumerate().map(|b| [(b.0 as f64 as f64), (b.1.1.clone() as f64 as f64) as f64] ).collect::<PlotPoints>()).name(plotcontext.plottables.get(a.0).unwrap().clone().name))
                                            })
                                }).response.context_menu(|ui| {
                                    if ui.checkbox(&mut plotcontext.draggable, "is draggable").changed() ||
                                    ui.checkbox(&mut plotcontext.axes, "show axes").changed() ||
                                    ui.checkbox(&mut plotcontext.scroll, "is scrollable").changed() ||
                                    ui.checkbox(&mut plotcontext.zoom, "is zoomable").changed() ||
                                    ui.checkbox(&mut plotcontext.legend, "show legend").changed() ||
                                    ui.checkbox(&mut plotcontext.grid, "show grid").changed() {
                                        ui.close_menu();
                                    }
                                });
    }
}

#[tokio::main]
async fn main() {    
    println!("start");
    let (mib_obj_sender, mib_obj_reciever): (Sender<MibObject>, Receiver<MibObject>) = std::sync::mpsc::channel();
    let (target_sender, target_reciever): (Sender<(SocketAddr, String)>, Receiver<(SocketAddr, String)>) = std::sync::mpsc::channel();

    fs::create_dir_all("/logs").expect("could not create directory");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("SNMP Monitor".to_string()).with_app_id("SNMP_Monitor").with_min_inner_size([854.0,480.0]).with_maximized(false),
        ..Default::default()
    };

    let mut dock_state: DockState<String> = DockState::new(vec![]);

    dock_state.translations.tab_context_menu.eject_button = "Undock".to_owned();

    // let [a, b] = dock_state.main_surface_mut().split_left(NodeIndex::root(), 0.3, vec!["Inspector".to_owned()]);
    // let [_, _] = dock_state.main_surface_mut().split_below(a, 0.7, vec!["File Browser".to_owned(), "Asset Manager".to_owned()]);
    // let [_, _] = dock_state.main_surface_mut().split_below(b, 0.5, vec!["Hierarchy".to_owned()]);

    let mut open_tabs = HashSet::new();

    for node in dock_state[SurfaceIndex::main()].iter() {
        if let Some(tabs) = node.tabs() {
            for tab in tabs {
                open_tabs.insert(tab.clone());
            }
        }
    }

    let context = MyContext {
        title: "Hello".to_string(),
        age: 24,
        style: None,
        open_tabs,
        object: None,
        plots: HashMap::new(),
        new_plot_name: "".to_owned(),

        show_window_close: true,
        show_window_collapse: true,
        show_close_buttons: true,
        show_add_buttons: false,
        draggable_tabs: true,
        show_tab_name_on_hover: false,
        allowed_splits: AllowedSplits::default(),
    };

    let app: AppCreator = Box::new(|_| Box::new(SnmpMonitorApp { 
        name: "SNMP_Monitor".to_owned(), 
        target_ip: "127.0.0.1".to_owned(), 
        community: "public".to_owned(), 
        mib_obj_reciever: mib_obj_reciever, 
        target_sender: target_sender,
        context: context,
        new_plot_window_manager: NewPlotWindowManager { open: false, show: false, value_to_add: None },
        tabs_tree: dock_state,
    }));

    println!("create task");

    let runtime = Builder::new_multi_thread()
                                .thread_stack_size(16 * 1024 * 1024)
                                .thread_name("monitoring_thread")
                                .worker_threads(1)
                                .enable_time()
                                .enable_io()
                                .build()
                                .unwrap();

    println!("run task");

    runtime.spawn(async move {
        println!("inside task");
        let mut interval = time::interval(Duration::from_secs(30));

        let mut target_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let mut community = "public".to_owned();

        // let currtime: DateTime<Local> = std::time::SystemTime::now().into();
        // let date = format!("{}", currtime.format("%Y_%m_%d %T"));

        // let mut writer = csv::WriterBuilder::new().from_path("monitor_log.csv").unwrap();

        let sock_addr = SocketAddr::from((target_ip.to_owned(), 161));

        let client_res = Snmp2cClient::new(
            sock_addr,
            community.as_bytes().to_vec().clone(),
            Some("0.0.0.0:0".parse().unwrap()),
            None,
        ).await;
        let mut client = client_res.expect("failed to create SNMP client");
        println!("start loop");

        'monitor_loop: loop {
            println!("loop repeat");
            interval.tick().await;
            
            match target_reciever.try_recv() {
                Ok(target) => {
                    println!("recieved target");
                    let client_res = Snmp2cClient::new(
                        target.0,
                        target.1.as_bytes().to_vec().clone(),
                        Some("0.0.0.0:0".parse().unwrap()),
                        None,
                    ).await;
                    client = client_res.expect("failed to create SNMP client");
                    println!("target is now {:?}", target);
                },
                Err(_) => {},
            };

            let mut object = MibObject::new();

            println!("sending snmp requests to {:?}", &client.target());

            object.walk(&client).await;
            
            println!("got snmp responses");
            
            println!("object size: {}", std::mem::size_of_val(&object));

            let log_file_name = format!("logs/MIB-log-{}.log", str::replace(&client.target().ip().to_string(), ".", "-"));

            println!("{}", log_file_name);

            let log = OpenOptions::new()
                                        .read(true)
                                        .append(true)
                                        .create(true)
                                        .open(log_file_name)
                                        .unwrap();
    
            let mut log_writer = LineWriter::new(log);

            log_writer.write_all([serde_json::to_string(&object).unwrap(), "\n".to_owned()].concat().as_bytes()).unwrap();

            // println!("{:?}, {:?}", &object.icmp.icmpOutMsgs.name, &object.icmp.icmpOutMsgs.value);

            // write!(log_writer, "{},\n", serde_json::to_string_pretty(&object).unwrap());
            // write!(log_writer, "{},\n", serde_json::to_string(&object).unwrap()).unwrap();
            // history_writer.flush().unwrap();

            mib_obj_sender.send(object).expect("msg");
        }

    });

    println!("run egui");

    eframe::run_native("SNMP Monitor", options, app).unwrap();
}

impl eframe::App for SnmpMonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let win_dimentions: Option<(f32, f32)> = (ctx.input(|i| match i.viewport().outer_rect {
                Some(rect) => Some((rect.width(), rect.height())),
                None => None,
            })
        );
        match self.mib_obj_reciever.try_recv() {
            Ok(mibobj) => {
                println!("recieved object");
                if !self.context.plots.is_empty() {
                    self.context.plots.clone().into_iter().for_each(|plot| {
                        plot.1.plottables.into_iter().enumerate().for_each(|plottable| {
                            self.context.plots.get_mut(&plot.0).unwrap().plottables.get_mut(plottable.0).unwrap().points.push((mibobj.timestamp, mibobj.find_oid(plottable.1.oid).unwrap().val_as_mvinti64().unwrap().first().unwrap().clone()));
                            // plottable.1.points.push((mibobj.timestamp, mibobj.find_oid(plottable.1.oid).unwrap().val_as_mvinti64().unwrap().first().unwrap().clone()));
                        })
                    });
                }
                self.context.object = Some(mibobj);
            },
            Err(_) => {},
        };
        if self.context.object.is_some() {
            egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.target_ip).hint_text("target ipaddress"));
                    ui.add(egui::TextEdit::singleline(&mut self.community).hint_text("target community string"));
                    if win_dimentions.is_some() {
                        if ui.add(egui::Button::new("change target")).clicked() {
                            self.target_sender.send((SocketAddr::from_str(&[&self.target_ip, ":161"].concat()).expect("couldnt convert ip to socketaddr"), self.community.to_owned())).expect("error sending target info");
                        }
                    }
                });
            });
            
            if self.new_plot_window_manager.show {
                Window::new("Create New Plot")
                    .vscroll(false)
                    .resizable(false)
                    .movable(false)
                    .fixed_pos([win_dimentions.unwrap().0 / 2.0, win_dimentions.unwrap().1 / 2.0])
                    .open(&mut self.new_plot_window_manager.open)
                    .show(ctx, |ui| {
                        ui.heading("enter new plot name");
                        ui.separator();
                        ui.add(
                            egui::TextEdit::singleline(&mut self.context.new_plot_name)
                                .hint_text("Plot Name"),
                        );
                        if ui.button("create plot").clicked() {
                            self.context.open_tabs.insert(self.context.new_plot_name.clone());
                            self.tabs_tree
                                .main_surface_mut()
                                .push_to_focused_leaf(self.context.new_plot_name.clone());
                            
                            let file_path = format!("logs/MIB-log-{}.log", str::replace(&self.target_ip, ".", "-"));
                            println!("{}", file_path);

                            let snmp_log: Vec<MibObject> = BufReader::new(File::open(file_path).unwrap())
                                                                        .lines()
                                                                        .map(|line| line.unwrap())
                                                                        .filter(|line| line != "")
                                                                        .map(|line| serde_json::from_str::<MibObject>(&line).unwrap())
                                                                        .collect::<Vec<MibObject>>();
    
                            snmp_log
                                .clone()
                                .into_iter()
                                .for_each(|obj| println!("\n{:?}\n", obj.ip.ipForwarding));
    
                            let mut plottables: Vec<Plottable> = vec![Plottable::new(self.new_plot_window_manager.value_to_add.clone().unwrap()).unwrap()];
                            snmp_log.into_iter().for_each(|obj| {
                                println!("{:?}", self.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid());
                                plottables[0].add((obj.timestamp, obj.find_oid(self.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid()).expect("couldnt find object by oid").val_as_mvinti64().expect("couldnt convert value to mvinti64").first().expect("no first value in vector").clone() ));
                            });
    
                            self.context
                                .plots
                                .insert(self.context.new_plot_name.clone(), PlotContext::new(plottables));
                            self.context.new_plot_name = "".to_string();
                        }
                    });
            } else {
                self.new_plot_window_manager.value_to_add = None;
                self.new_plot_window_manager.open = false;
            }

            self.context.object.clone().unwrap().egui_show(ctx, self);
            


            egui::CentralPanel::default().frame(Frame::none().inner_margin(0.0)).show(ctx, |ui| {
                DockArea::new(&mut self.tabs_tree)
                        .show_close_buttons(self.context.show_close_buttons)
                        .show_add_buttons(self.context.show_add_buttons)
                        .draggable_tabs(self.context.draggable_tabs)
                        .show_tab_name_on_hover(self.context.show_tab_name_on_hover)
                        .allowed_splits(self.context.allowed_splits)
                        .show_window_close_buttons(self.context.show_window_close)
                        .show_window_collapse_buttons(self.context.show_window_collapse)
                        .show_inside(ui, &mut self.context);
            });
        } else {
            egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
                ui.heading("top panel");
            });
            egui::SidePanel::left("side_panel").show(ctx, |ui| {
                ui.heading("side panel");
                ui.label("no objects found");
                ui.spinner();
            });
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("center panel");
            });
        }
    }
}