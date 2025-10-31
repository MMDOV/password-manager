use color_eyre::Result;
use crossterm::event::{self, Event};
use ratatui::{
    DefaultTerminal, Frame,
    style::{Style, Stylize},
    widgets::{Block, List},
};

pub fn run_tui() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let result = run(terminal);
    ratatui::restore();
    result
}

fn run(mut terminal: DefaultTerminal) -> Result<()> {
    loop {
        terminal.draw(render)?;
        if matches!(event::read()?, Event::Key(_)) {
            break Ok(());
        }
    }
}

fn render(frame: &mut Frame) {
    let items = ["Item 1", "Item 2", "Item 3"];
    let list = List::new(items)
        .block(Block::bordered().title("List"))
        .highlight_style(Style::new().reversed())
        .highlight_symbol(">>")
        .repeat_highlight_symbol(true);
    frame.render_widget(list, frame.area());
}
