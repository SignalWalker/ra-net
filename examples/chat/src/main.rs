use iced::{widget, Application, Command};

fn main() -> iced::Result {
    Chat::run(iced::Settings {
        window: iced::window::Settings {
            size: (640, 480),
            ..Default::default()
        },
        ..Default::default()
    })
}

#[derive(Debug, Clone)]
pub enum Message {}

pub struct Chat {
    // sock: RtpSocket,
}

impl Application for Chat {
    type Executor = iced::executor::Default;

    type Message = Message;

    type Theme = iced::theme::Theme;

    type Flags = ();

    fn new(_: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        (Self {}, Command::none())
    }

    fn title(&self) -> String {
        "SneedChat".into()
    }

    fn update(&mut self, _: Self::Message) -> iced::Command<Self::Message> {
        Command::none()
    }

    fn view(&self) -> iced::Element<'_, Self::Message, iced::Renderer<Self::Theme>> {
        use widget as w;
        w::container(w::row![w::button("Edit")]).into()
    }
}
